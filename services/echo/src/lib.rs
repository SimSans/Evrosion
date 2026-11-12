//! Initial typed echo service startup policy. All authority is explicitly granted.
#![no_std]
#![forbid(unsafe_code)]

use ev_userspace_contract::Bootstrap;

pub const SELECTOR_REQUEST: u64 = 3;
pub const SELECTOR_RESPONSE: u64 = 4;
pub const RECEIVE_CONTROL: u16 = 16 | 256;
pub const SEND: u16 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub requests: u64,
    pub responses: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Bootstrap(ev_userspace_contract::Error),
    MissingGrant,
    Authority,
}

pub fn startup(bytes: &[u8]) -> Result<Capabilities, Error> {
    let bootstrap = Bootstrap::parse(bytes).map_err(Error::Bootstrap)?;
    let request = bootstrap
        .find(SELECTOR_REQUEST)
        .ok_or(Error::MissingGrant)?;
    let response = bootstrap
        .find(SELECTOR_RESPONSE)
        .ok_or(Error::MissingGrant)?;
    if bootstrap.grants().count() != 2
        || request.kind != 2
        || request.rights != RECEIVE_CONTROL
        || response.kind != 2
        || response.rights != SEND
    {
        return Err(Error::Authority);
    }
    Ok(Capabilities {
        requests: request.handle,
        responses: response.handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::{Context, Grant, encode};

    fn context() -> Context {
        Context {
            epoch: 7,
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
                selector: SELECTOR_REQUEST,
                handle: 512,
                kind: 2,
                rights: RECEIVE_CONTROL,
            },
            Grant {
                selector: SELECTOR_RESPONSE,
                handle: 513,
                kind: 2,
                rights: SEND,
            },
        ]
    }

    #[test]
    fn startup_accepts_only_the_explicit_request_receive_and_response_send() {
        let bytes = encode(context(), &grants()).unwrap();
        assert_eq!(
            startup(&bytes),
            Ok(Capabilities {
                requests: 512,
                responses: 513
            })
        );
        let bytes = encode(context(), &grants()[..1]).unwrap();
        assert_eq!(startup(&bytes), Err(Error::MissingGrant));
    }

    #[test]
    fn wrong_kinds_excess_rights_and_unnecessary_grants_fail_closed() {
        for field in 0..4 {
            let mut g = grants();
            match field {
                0 => {
                    g[0].kind = 1;
                    g[0].rights = 1;
                }
                1 => g[0].rights |= SEND,
                2 => g[1].rights |= 16,
                _ => g[0].rights = 16,
            }
            let bytes = encode(context(), &g).unwrap();
            assert_eq!(startup(&bytes), Err(Error::Authority));
        }
        let [request, response] = grants();
        let extra = Grant {
            selector: 5,
            handle: 514,
            kind: 1,
            rights: 1,
        };
        let bytes = encode(context(), &[request, response, extra]).unwrap();
        assert_eq!(startup(&bytes), Err(Error::Authority));
    }

    #[test]
    fn truncated_bootstrap_and_zero_handles_never_become_service_authority() {
        let mut bytes = encode(context(), &grants()).unwrap();
        for length in 0..bytes.len() {
            assert_eq!(
                startup(&bytes[..length]),
                Err(Error::Bootstrap(ev_userspace_contract::Error::Length))
            );
        }
        bytes[152..160].fill(0);
        assert_eq!(
            startup(&bytes),
            Err(Error::Bootstrap(ev_userspace_contract::Error::Grant))
        );
    }
}
