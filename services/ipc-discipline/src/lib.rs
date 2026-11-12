//! Exact Internal authority and role layout for bounded IPC discipline fixtures.
#![no_std]
#![forbid(unsafe_code)]
use ev_userspace_contract::Bootstrap;
pub const STACK1_PAGE: u64 = 0x8000100000;
pub const STACK2_PAGE: u64 = 0x8000102000;
pub const STACK1_TOP: u64 = STACK1_PAGE + 4096;
pub const STACK2_TOP: u64 = STACK2_PAGE + 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pair {
    pub incoming: u64,
    pub outgoing: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub pairs: [Pair; 3],
    pub mutex: Option<u64>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Bootstrap(ev_userspace_contract::Error),
    Count,
    Missing,
    Authority,
}
pub fn rank(process_index: u64, local_role: u64) -> Option<u8> {
    if process_index < 3 && local_role < 3 {
        Some((process_index + 3 * local_role) as u8)
    } else {
        None
    }
}
pub fn startup(bytes: &[u8], depth: bool) -> Result<Capabilities, Error> {
    let bootstrap = Bootstrap::parse(bytes).map_err(Error::Bootstrap)?;
    if bootstrap.grants().count() != if depth { 6 } else { 7 } {
        return Err(Error::Count);
    }
    let mut pairs = [Pair {
        incoming: 0,
        outgoing: 0,
    }; 3];
    for (i, pair) in pairs.iter_mut().enumerate() {
        let incoming = bootstrap.find(1 + 2 * i as u64).ok_or(Error::Missing)?;
        let outgoing = bootstrap.find(2 + 2 * i as u64).ok_or(Error::Missing)?;
        if incoming.kind != 2
            || incoming.rights != 272
            || outgoing.kind != 2
            || outgoing.rights != 8
        {
            return Err(Error::Authority);
        }
        *pair = Pair {
            incoming: incoming.handle,
            outgoing: outgoing.handle,
        };
    }
    let mutex = if depth {
        None
    } else {
        let grant = bootstrap.find(7).ok_or(Error::Missing)?;
        if grant.kind != 6 || grant.rights != 256 {
            return Err(Error::Authority);
        }
        Some(grant.handle)
    };
    Ok(Capabilities { pairs, mutex })
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
            limits: [512, 16, 1, 3],
            manifest: [1; 32],
            authority: [2; 32],
        }
    }
    fn grants() -> [Grant; 7] {
        core::array::from_fn(|i| Grant {
            selector: i as u64 + 1,
            handle: i as u64 + 256,
            kind: if i == 6 { 6 } else { 2 },
            rights: if i == 6 {
                256
            } else if i % 2 == 0 {
                272
            } else {
                8
            },
        })
    }
    #[test]
    fn rank_is_fixture_routing_metadata_and_every_actual_role_is_bounded() {
        let mut seen = [false; 9];
        for process in 0..3 {
            for local in 0..3 {
                let rank = rank(process, local).unwrap();
                assert!(!seen[rank as usize]);
                seen[rank as usize] = true;
            }
        }
        assert!(seen.into_iter().all(|value| value));
        for (process, local) in [(3, 0), (0, 3), (u64::MAX, u64::MAX)] {
            assert_eq!(rank(process, local), None);
        }
    }
    #[test]
    fn depth_has_six_endpoint_roles_and_chain_also_has_exact_mutex_control() {
        let g = grants();
        assert!(startup(&encode(context(), &g[..6]).unwrap(), true).is_ok());
        assert!(startup(&encode(context(), &g).unwrap(), false).is_ok());
        assert_eq!(
            startup(&encode(context(), &g[..6]).unwrap(), false),
            Err(Error::Count)
        );
        assert_eq!(
            startup(&encode(context(), &g).unwrap(), true),
            Err(Error::Count)
        );
        for i in 0..7 {
            let mut wrong = g;
            wrong[i].rights |= 32;
            assert_eq!(
                startup(&encode(context(), &wrong).unwrap(), false),
                Err(Error::Authority)
            );
        }
    }
    #[test]
    fn malformed_or_truncated_record_cannot_become_role_authority() {
        let mut bytes = encode(context(), &grants()).unwrap();
        for length in 0..bytes.len() {
            assert!(startup(&bytes[..length], false).is_err());
        }
        bytes[152..160].fill(0);
        assert!(startup(&bytes, false).is_err());
        assert_eq!(STACK2_PAGE - STACK1_PAGE, 8192);
        assert_eq!(STACK1_TOP, STACK1_PAGE + 4096);
        assert_eq!(STACK2_TOP, STACK2_PAGE + 4096);
    }
}
