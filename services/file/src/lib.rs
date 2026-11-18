//! Exact measured startup roles for the scoped File/Object service and app.
#![no_std]
#![forbid(unsafe_code)]
use ev_userspace_contract::Bootstrap;
pub mod desktop_frame;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerCaps {
    pub io: u64,
    pub block: u64,
    pub app: u64,
    pub read_only: u64,
    pub read_write: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppCaps {
    pub app: u64,
    pub read_only: u64,
    pub read_write: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DesktopCaps {
    pub io: u64,
    pub block: u64,
    pub app: u64,
    pub notes_ro: u64,
    pub notes_rw: u64,
    pub private_ro: u64,
    pub private_rw: u64,
    pub events: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Bootstrap(ev_userspace_contract::Error),
    Count,
    Limits,
    Authority,
}
fn validate<'a>(bytes: &'a [u8], roles: &[(u64, u8, u16)]) -> Result<Bootstrap<'a>, Error> {
    validate_limits(bytes, roles, [2048, 32, 1, 1])
}
fn validate_limits<'a>(
    bytes: &'a [u8],
    roles: &[(u64, u8, u16)],
    limits: [u64; 4],
) -> Result<Bootstrap<'a>, Error> {
    let startup = Bootstrap::parse(bytes).map_err(Error::Bootstrap)?;
    for (i, value) in limits.into_iter().enumerate() {
        if bytes[40 + i * 8..48 + i * 8] != value.to_le_bytes() {
            return Err(Error::Limits);
        }
    }
    if startup.grants().count() != roles.len() {
        return Err(Error::Count);
    }
    for &(selector, kind, rights) in roles {
        let grant = startup.find(selector).ok_or(Error::Authority)?;
        if grant.kind != kind || grant.rights != rights {
            return Err(Error::Authority);
        }
    }
    Ok(startup)
}
pub fn server_startup(bytes: &[u8]) -> Result<ServerCaps, Error> {
    let s = validate(
        bytes,
        &[(1, 1, 7), (2, 2, 8), (3, 1, 7), (4, 2, 272), (5, 2, 272)],
    )?;
    Ok(ServerCaps {
        io: s.find(1).ok_or(Error::Authority)?.handle,
        block: s.find(2).ok_or(Error::Authority)?.handle,
        app: s.find(3).ok_or(Error::Authority)?.handle,
        read_only: s.find(4).ok_or(Error::Authority)?.handle,
        read_write: s.find(5).ok_or(Error::Authority)?.handle,
    })
}
pub fn app_startup(bytes: &[u8]) -> Result<AppCaps, Error> {
    let s = validate(bytes, &[(1, 1, 7), (2, 2, 8), (3, 2, 8)])?;
    Ok(AppCaps {
        app: s.find(1).ok_or(Error::Authority)?.handle,
        read_only: s.find(2).ok_or(Error::Authority)?.handle,
        read_write: s.find(3).ok_or(Error::Authority)?.handle,
    })
}
pub fn desktop_startup(bytes: &[u8]) -> Result<DesktopCaps, Error> {
    let startup = validate_limits(
        bytes,
        &[
            (1, 1, 7),
            (2, 2, 8),
            (3, 1, 7),
            (4, 2, 272),
            (5, 2, 272),
            (6, 2, 272),
            (7, 2, 272),
            (8, 2, 8),
        ],
        ev_userspace_contract::root_v2::catalogue::CHILD_LIMITS,
    )?;
    let mut handles = [0; 8];
    for (index, grant) in startup.grants().enumerate() {
        if handles[..index].contains(&grant.handle) {
            return Err(Error::Authority);
        }
        handles[index] = grant.handle;
    }
    Ok(DesktopCaps {
        io: handles[0],
        block: handles[1],
        app: handles[2],
        notes_ro: handles[3],
        notes_rw: handles[4],
        private_ro: handles[5],
        private_rw: handles[6],
        events: handles[7],
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::{Context, Grant, encode};
    fn context() -> Context {
        Context {
            epoch: 1,
            incarnation: 1,
            process: 1,
            limits: [2048, 32, 1, 1],
            manifest: [1; 32],
            authority: [2; 32],
        }
    }
    #[test]
    fn exact_file_roles_never_grant_app_ports_or_backend_endpoint() {
        let grants = [
            Grant {
                selector: 1,
                handle: 11,
                kind: 1,
                rights: 7,
            },
            Grant {
                selector: 2,
                handle: 22,
                kind: 2,
                rights: 8,
            },
            Grant {
                selector: 3,
                handle: 33,
                kind: 2,
                rights: 8,
            },
        ];
        let bytes = encode(context(), &grants).unwrap();
        let caps = app_startup(&bytes).unwrap();
        assert_eq!(caps.app, 11);
        assert_eq!(caps.read_only, 22);
        assert_eq!(caps.read_write, 33);
        let mut bad = grants;
        bad[1].kind = 7;
        bad[1].rights = 3;
        assert_eq!(
            app_startup(&encode(context(), &bad).unwrap()),
            Err(Error::Authority)
        );
        let mut c = context();
        c.limits[0] = 1024;
        assert_eq!(
            app_startup(&encode(c, &grants).unwrap()),
            Err(Error::Limits)
        );
    }
    #[test]
    fn server_requires_two_separate_receive_routes_and_two_exact_memory_roles() {
        let grants = [
            Grant {
                selector: 1,
                handle: 11,
                kind: 1,
                rights: 7,
            },
            Grant {
                selector: 2,
                handle: 22,
                kind: 2,
                rights: 8,
            },
            Grant {
                selector: 3,
                handle: 33,
                kind: 1,
                rights: 7,
            },
            Grant {
                selector: 4,
                handle: 44,
                kind: 2,
                rights: 272,
            },
            Grant {
                selector: 5,
                handle: 55,
                kind: 2,
                rights: 272,
            },
        ];
        let bytes = encode(context(), &grants).unwrap();
        let caps = server_startup(&bytes).unwrap();
        assert_eq!(
            (caps.io, caps.app, caps.read_only, caps.read_write),
            (11, 33, 44, 55)
        );
        let mut bad = grants;
        bad[4].rights |= 8;
        assert_eq!(
            server_startup(&encode(context(), &bad).unwrap()),
            Err(Error::Authority)
        );
        assert_eq!(
            server_startup(&encode(context(), &grants[..4]).unwrap()),
            Err(Error::Count)
        );
    }
    #[test]
    fn desktop_requires_four_object_routes_and_rejects_legacy_or_alias_profiles() {
        let grants = core::array::from_fn::<_, 8, _>(|index| {
            let (kind, rights) = [
                (1, 7),
                (2, 8),
                (1, 7),
                (2, 272),
                (2, 272),
                (2, 272),
                (2, 272),
                (2, 8),
            ][index];
            Grant {
                selector: index as u64 + 1,
                handle: 256 + index as u64,
                kind,
                rights,
            }
        });
        let mut desktop_context = context();
        desktop_context.limits = ev_userspace_contract::root_v2::catalogue::CHILD_LIMITS;
        let bytes = encode(desktop_context, &grants).unwrap();
        let caps = desktop_startup(&bytes).unwrap();
        if context().limits != desktop_context.limits {
            assert_eq!(
                desktop_startup(&encode(context(), &grants).unwrap()),
                Err(Error::Limits)
            );
        }
        assert_eq!(caps.notes_ro, 259);
        assert_eq!(caps.private_ro, 261);
        assert_ne!(caps.notes_ro, caps.private_ro);
        assert!(server_startup(&bytes).is_err());
        assert!(desktop_startup(&encode(desktop_context, &grants[..5]).unwrap()).is_err());
        for index in 0..8 {
            let mut wrong = grants;
            wrong[index].rights ^= 128;
            assert!(desktop_startup(&encode(desktop_context, &wrong).unwrap()).is_err());
        }
        let mut aliases = grants;
        aliases[5].handle = aliases[3].handle;
        assert!(desktop_startup(&encode(desktop_context, &aliases).unwrap()).is_err());
    }
}
