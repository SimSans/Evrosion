//! Selected M8 Input role shape. Parsed handles are descriptive; actual Kernel
//! V5 admission fixes the exclusive PIO scope and Root-only barrier receiver.
use ev_userspace_contract::Bootstrap;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bootstrap,
    Limits,
    Roles,
}
pub struct Profile {
    pub ports: u64,
    pub events: u64,
    pub control: u64,
}
impl Profile {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let b = Bootstrap::parse(bytes).map_err(|_| Error::Bootstrap)?;
        let limits: [u64; 4] = core::array::from_fn(|i| {
            u64::from_le_bytes(bytes[40 + i * 8..48 + i * 8].try_into().unwrap())
        });
        if limits != ev_userspace_contract::root_v5::resources::JOB_TEMPLATE_LIMITS[0] {
            return Err(Error::Limits);
        }
        Self::roles(&b)
    }
    /// The native entry first validates the complete selected profile. This
    /// second shape check extracts exact handles without a raw startup reread.
    pub fn roles(b: &Bootstrap<'_>) -> Result<Self, Error> {
        if b.grants().count() != 3 {
            return Err(Error::Roles);
        }
        let specs = [(7, 3), (2, 8), (2, 272)];
        let mut handles = [0; 3];
        for (i, g) in b.grants().enumerate() {
            if g.selector != i as u64 + 1
                || (g.kind, g.rights) != specs[i]
                || handles[..i].contains(&g.handle)
            {
                return Err(Error::Roles);
            }
            handles[i] = g.handle;
        }
        Ok(Self {
            ports: handles[0],
            events: handles[1],
            control: handles[2],
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::{Context, Grant, encode};
    fn context() -> Context {
        Context {
            epoch: 805,
            incarnation: 1,
            process: 7,
            limits: ev_userspace_contract::root_v5::resources::JOB_TEMPLATE_LIMITS[0],
            manifest: [1; 32],
            authority: [2; 32],
        }
    }
    #[test]
    fn selected_three_roles_are_exact_and_legacy_four_never_silently_reinterpreted() {
        let grants = [
            Grant {
                selector: 1,
                handle: 11,
                kind: 7,
                rights: 3,
            },
            Grant {
                selector: 2,
                handle: 12,
                kind: 2,
                rights: 8,
            },
            Grant {
                selector: 3,
                handle: 13,
                kind: 2,
                rights: 272,
            },
        ];
        let bytes = encode(context(), &grants).unwrap();
        let p = Profile::parse(&bytes).unwrap();
        assert_eq!((p.ports, p.events, p.control), (11, 12, 13));
        let mut old = context();
        old.limits = [16384, 32, 1, 1];
        assert!(matches!(
            Profile::parse(&encode(old, &grants).unwrap()),
            Err(Error::Limits)
        ));
        let mut wrong = grants;
        wrong[1].rights |= 64;
        assert!(matches!(
            Profile::parse(&encode(context(), &wrong).unwrap()),
            Err(Error::Roles)
        ));
        let old = [
            grants[0],
            grants[1],
            Grant {
                selector: 3,
                handle: 14,
                kind: 2,
                rights: 8,
            },
            Grant {
                selector: 4,
                handle: 15,
                kind: 2,
                rights: 272,
            },
        ];
        assert!(Profile::parse(&encode(context(), &old).unwrap()).is_err());
        let mut c = context();
        c.limits[1] = 128;
        assert!(matches!(
            Profile::parse(&encode(c, &grants).unwrap()),
            Err(Error::Limits)
        ));
        let mut alias = grants;
        alias[2].handle = alias[1].handle;
        assert!(matches!(
            Profile::parse(&encode(context(), &alias).unwrap()),
            Err(Error::Roles)
        ));
    }
    #[test]
    fn raw_pointer_bytes_keep_full_relative_range_and_sequence_without_absolute_geometry() {
        for (dx, dy) in [(-256, 255), (255, -256), (0, 0)] {
            let event = ev_input::pointer::PointerEvent {
                dx,
                dy,
                buttons: 7,
                sequence: 0xfeed_beef,
            };
            let bytes = event.encode().unwrap();
            assert_eq!(bytes[0], b'P');
            assert_eq!(ev_input::pointer::PointerEvent::decode(bytes), Ok(event));
        }
    }
}
