//! Exact measured startup policy for the capability-bearing Echo proof actor.
#![no_std]
#![forbid(unsafe_code)]
use ev_userspace_contract::Bootstrap;

pub const LIMITS: [u64; 4] = [512, 16, 1, 1];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub requests: u64,
    pub responses: u64,
}

#[derive(Debug, PartialEq, Eq)]
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
    for (selector, kind, rights) in [(3, 2, 272), (4, 2, 8)] {
        let grant = bootstrap.find(selector).ok_or(Error::MissingGrant)?;
        if grant.kind != kind || grant.rights != rights {
            return Err(Error::Authority);
        }
    }
    Ok(Capabilities {
        requests: bootstrap.find(3).ok_or(Error::MissingGrant)?.handle,
        responses: bootstrap.find(4).ok_or(Error::MissingGrant)?.handle,
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
            limits: LIMITS,
            manifest: [2; 32],
            authority: [3; 32],
        }
    }
    fn grants() -> [Grant; 2] {
        [
            Grant {
                selector: 3,
                handle: 514,
                kind: 2,
                rights: 272,
            },
            Grant {
                selector: 4,
                handle: 515,
                kind: 2,
                rights: 8,
            },
        ]
    }
    #[test]
    fn exact_roles_are_required_with_no_unnecessary_authority() {
        assert!(startup(&encode(context(), &grants()).unwrap()).is_ok());
        assert_eq!(
            startup(&encode(context(), &grants()[..1]).unwrap()),
            Err(Error::GrantCount)
        );
        let mut wrong = grants();
        wrong[0].selector = 99;
        // Keep records canonical while making the required selector absent.
        wrong.sort_by_key(|grant| grant.selector);
        assert_eq!(
            startup(&encode(context(), &wrong).unwrap()),
            Err(Error::MissingGrant)
        );
    }
    #[test]
    fn kind_and_rights_are_exact_not_subsets() {
        for i in 0..grants().len() {
            let mut wrong = grants();
            wrong[i].kind = 5;
            wrong[i].rights = 1;
            assert_eq!(
                startup(&encode(context(), &wrong).unwrap()),
                Err(Error::Authority)
            );
            let mut wrong = grants();
            wrong[i].rights |= 128;
            assert_eq!(
                startup(&encode(context(), &wrong).unwrap()),
                Err(Error::Authority)
            );
        }
    }
    #[test]
    fn truncated_records_and_forged_zero_handles_fail_closed() {
        let mut bytes = encode(context(), &grants()).unwrap();
        for length in 0..bytes.len() {
            assert!(startup(&bytes[..length]).is_err());
        }
        bytes[152..160].fill(0);
        assert_eq!(
            startup(&bytes),
            Err(Error::Bootstrap(ev_userspace_contract::Error::Grant))
        );
    }
}
