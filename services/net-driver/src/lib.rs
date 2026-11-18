//! Actual userspace byte-PIO adapter for the qualified QEMU ISA NE2000 profile.
//! Kernel authority remains in live IoPorts capabilities; protocols/policy do
//! not live in this adapter. Host tests use the same driver with fake I/O.
#![no_std]
#![forbid(unsafe_code)]

pub mod clock;
#[cfg(feature = "stack-service")]
pub mod control;
pub mod device;
pub mod diagnostic;
pub mod mediated;
#[cfg(feature = "stack-service")]
pub mod network;
pub mod protocol;
#[cfg(feature = "stack-service")]
pub mod pump;
pub mod rpc_service;
pub mod startup;

/// Explicit local-development MAC; the trusted producer must configure the
/// same actual QEMU device and scope its port object. Not a hardware identity.
pub const REFERENCE_MAC: [u8; 6] = [0x02, 0x45, 0x56, 0x52, 0x00, 0x01];

/// A minimal cold probe uses one exact existing v1 bootstrap grant. The actual
/// Kernel binding, not the numeric selector/handle, determines the device.
pub fn probe_startup(bytes: &[u8]) -> Result<u64, StartupError> {
    let startup =
        ev_userspace_contract::Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    if startup.grants().count() != 1 {
        return Err(StartupError::Authority);
    }
    let ports = startup.find(1).ok_or(StartupError::Authority)?;
    if ports.kind != 7 || ports.rights != 3 {
        return Err(StartupError::Authority);
    }
    Ok(ports.handle)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupError {
    Bootstrap(ev_userspace_contract::Error),
    Authority,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::{Context, Grant, encode};

    #[test]
    fn probe_accepts_only_the_exact_single_port_role() {
        let context = Context {
            epoch: 1,
            incarnation: 1,
            process: 1,
            limits: [4096, 32, 1, 1],
            manifest: [1; 32],
            authority: [2; 32],
        };
        let grant = Grant {
            selector: 1,
            handle: 7,
            kind: 7,
            rights: 3,
        };
        assert_eq!(probe_startup(&encode(context, &[grant]).unwrap()), Ok(7));
        for bad in [
            Grant { rights: 1, ..grant },
            Grant {
                kind: 2,
                rights: 8,
                ..grant
            },
            Grant {
                selector: 2,
                ..grant
            },
        ] {
            assert_eq!(
                probe_startup(&encode(context, &[bad]).unwrap()),
                Err(StartupError::Authority)
            );
        }
        let extra = Grant {
            selector: 2,
            handle: 8,
            kind: 2,
            rights: 8,
        };
        assert_eq!(
            probe_startup(&encode(context, &[grant, extra]).unwrap()),
            Err(StartupError::Authority)
        );
    }
}
