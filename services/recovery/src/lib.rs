//! Independent recovery entry policy. No Root or normal service-graph linkage.
#![no_std]
#![forbid(unsafe_code)]
use ev_userspace_contract::{Bootstrap, READ, SELECTOR_EVENTS, SELECTOR_PROBE, SEND};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub probe: u64,
    pub events: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bootstrap(ev_userspace_contract::Error),
    GrantCount,
    MissingGrant,
    Authority,
}
pub fn startup(bytes: &[u8]) -> Result<Capabilities, Error> {
    let bootstrap = Bootstrap::parse(bytes).map_err(Error::Bootstrap)?;
    if bootstrap.grants().count() != 2 {
        return Err(Error::GrantCount);
    }
    let probe = bootstrap.find(SELECTOR_PROBE).ok_or(Error::MissingGrant)?;
    let events = bootstrap.find(SELECTOR_EVENTS).ok_or(Error::MissingGrant)?;
    if probe.kind != 1 || probe.rights != READ || events.kind != 2 || events.rights != SEND {
        return Err(Error::Authority);
    }
    Ok(Capabilities {
        probe: probe.handle,
        events: events.handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::{Context, Grant, encode};
    fn context() -> Context {
        Context {
            epoch: 27,
            incarnation: 1,
            process: 9,
            limits: [64, 16, 1, 1],
            manifest: [4; 32],
            authority: [5; 32],
        }
    }
    fn grants() -> [Grant; 2] {
        [
            Grant {
                selector: SELECTOR_PROBE,
                handle: 512,
                kind: 1,
                rights: READ,
            },
            Grant {
                selector: SELECTOR_EVENTS,
                handle: 513,
                kind: 2,
                rights: SEND,
            },
        ]
    }
    #[test]
    fn only_exact_recovery_roles_produce_the_explicit_handles() {
        let bytes = encode(context(), &grants()).unwrap();
        assert_eq!(
            startup(&bytes),
            Ok(Capabilities {
                probe: 512,
                events: 513
            })
        );
        assert_eq!(
            startup(&encode(context(), &grants()[..1]).unwrap()),
            Err(Error::GrantCount)
        );
        let extra = [
            grants()[0],
            grants()[1],
            Grant {
                selector: 3,
                handle: 514,
                kind: 5,
                rights: 256,
            },
        ];
        assert_eq!(
            startup(&encode(context(), &extra).unwrap()),
            Err(Error::GrantCount)
        );
    }
    #[test]
    fn wrong_roles_and_excess_authority_never_become_recovery_capabilities() {
        for damage in 0..6 {
            let mut g = grants();
            match damage {
                0 => g[0].rights |= 2,
                1 => g[0].rights |= 32,
                2 => g[1].rights |= 16,
                3 => g[1].rights |= 256,
                4 => g[0].kind = 3,
                _ => {
                    g[1].kind = 1;
                    g[1].rights = READ;
                }
            }
            assert_eq!(
                startup(&encode(context(), &g).unwrap()),
                Err(Error::Authority)
            );
        }
        let mut g = grants();
        g[1].selector = 3;
        assert_eq!(
            startup(&encode(context(), &g).unwrap()),
            Err(Error::MissingGrant)
        );
    }
    #[test]
    fn malformed_bootstrap_and_zero_handles_fail_closed() {
        let bytes = encode(context(), &grants()).unwrap();
        for length in 0..bytes.len() {
            assert_eq!(
                startup(&bytes[..length]),
                Err(Error::Bootstrap(ev_userspace_contract::Error::Length))
            );
        }
        let mut invalid = bytes;
        invalid[12] = 1;
        assert_eq!(
            startup(&invalid),
            Err(Error::Bootstrap(ev_userspace_contract::Error::Reserved))
        );
        let mut invalid = bytes;
        invalid[152..160].fill(0);
        assert_eq!(
            startup(&invalid),
            Err(Error::Bootstrap(ev_userspace_contract::Error::Grant))
        );
    }
}
