//! Initial Root Supervisor startup policy. No ambient authority or kernel linkage.
#![no_std]
#![forbid(unsafe_code)]
use ev_userspace_contract::{Bootstrap, READ, SELECTOR_EVENTS, SELECTOR_PROBE, SEND};
#[derive(Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub probe: u64,
    pub events: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Bootstrap(ev_userspace_contract::Error),
    MissingGrant,
    Authority,
}
pub fn startup(bytes: &[u8]) -> Result<Capabilities, Error> {
    let b = Bootstrap::parse(bytes).map_err(Error::Bootstrap)?;
    let probe = b.find(SELECTOR_PROBE).ok_or(Error::MissingGrant)?;
    let events = b.find(SELECTOR_EVENTS).ok_or(Error::MissingGrant)?;
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
            epoch: 1,
            incarnation: 2,
            process: 3,
            limits: [100, 64, 4, 8],
            manifest: [5; 32],
            authority: [6; 32],
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
    fn startup_uses_only_the_two_explicit_typed_handles() {
        let bytes = encode(context(), &grants()).unwrap();
        assert_eq!(
            startup(&bytes),
            Ok(Capabilities {
                probe: 512,
                events: 513
            })
        );
        let bytes = encode(context(), &grants()[..1]).unwrap();
        assert_eq!(startup(&bytes), Err(Error::MissingGrant));
    }
    #[test]
    fn unexpected_authority_and_malformed_bootstrap_fail_closed() {
        for field in 0..3 {
            let mut g = grants();
            match field {
                0 => g[0].rights |= 2,
                1 => g[1].rights |= 16,
                _ => g[0].kind = 3,
            }
            let bytes = encode(context(), &g).unwrap();
            assert_eq!(startup(&bytes), Err(Error::Authority));
        }
        let mut bytes = encode(context(), &grants()).unwrap();
        bytes[152..160].fill(0);
        assert_eq!(
            startup(&bytes),
            Err(Error::Bootstrap(ev_userspace_contract::Error::Grant))
        );
    }
}

#[cfg(feature = "desktop-contract")]
pub mod desktop_plan;

#[cfg(feature = "native-contract")]
pub mod native_plan;

#[cfg(feature = "native-contract")]
pub mod native_diagnostics;
