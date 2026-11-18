//! Exact roles for separately measured source actors. Numeric roles/addresses
//! are a layout contract; actual mappings, caps and identities remain Kernel
//! and supervisor admission responsibilities.
use crate::StartupError;
use ev_userspace_contract::Bootstrap;

pub const STARTUP_ADDRESS: usize = 0x80001fd000;
pub const NIC_WINDOW_ADDRESS: usize = 0x80001fc000;
pub const CLIENT_WINDOW_ADDRESS: usize = 0x80001fb000;
pub const DRIVER_READY: [u8; 8] = *b"EVNDRDY1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverCaps {
    pub ports: u64,
    pub window: u64,
    pub requests: u64,
    pub events: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkCaps {
    pub window: u64,
    pub driver: u64,
    pub client_window: u64,
    pub clients: u64,
    pub events: u64,
    pub incarnation: u64,
}
#[cfg(feature = "workspace-profile")]
fn m8_limits(bytes: &[u8], template: usize) -> Result<(), StartupError> {
    Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    let actual = core::array::from_fn::<_, 4, _>(|i| {
        u64::from_le_bytes(bytes[40 + i * 8..48 + i * 8].try_into().unwrap())
    });
    if actual != ev_userspace_contract::root_v5::resources::JOB_TEMPLATE_LIMITS[template] {
        return Err(StartupError::Authority);
    }
    Ok(())
}
/// Separate exact selected profile; legacy network() keeps its old behavior.
#[cfg(feature = "workspace-profile")]
pub fn network_m8(bytes: &[u8]) -> Result<NetworkCaps, StartupError> {
    m8_limits(bytes, 1)?;
    network(bytes)
}
/// Separate exact selected profile; legacy driver() keeps its old behavior.
#[cfg(feature = "workspace-profile")]
pub fn driver_m8(bytes: &[u8]) -> Result<DriverCaps, StartupError> {
    m8_limits(bytes, 0)?;
    driver(bytes)
}
pub fn network(bytes: &[u8]) -> Result<NetworkCaps, StartupError> {
    let startup = Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    let expected = [(1, 1, 7), (2, 2, 8), (3, 1, 7), (4, 2, 272), (5, 2, 8)];
    if startup.grants().count() != expected.len() {
        return Err(StartupError::Authority);
    }
    let mut handles = [0; 5];
    for (index, (actual, (selector, kind, rights))) in startup.grants().zip(expected).enumerate() {
        if actual.selector != selector
            || actual.kind != kind
            || actual.rights != rights
            || handles[..index].contains(&actual.handle)
        {
            return Err(StartupError::Authority);
        }
        handles[index] = actual.handle;
    }
    Ok(NetworkCaps {
        window: handles[0],
        driver: handles[1],
        client_window: handles[2],
        clients: handles[3],
        events: handles[4],
        incarnation: startup.incarnation(),
    })
}

pub fn driver(bytes: &[u8]) -> Result<DriverCaps, StartupError> {
    let startup = Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    let expected = [(1, 7, 3), (2, 1, 7), (3, 2, 272), (4, 2, 8)];
    if startup.grants().count() != expected.len() {
        return Err(StartupError::Authority);
    }
    let mut handles = [0; 4];
    for (index, (actual, (selector, kind, rights))) in startup.grants().zip(expected).enumerate() {
        if actual.selector != selector
            || actual.kind != kind
            || actual.rights != rights
            || handles[..index].contains(&actual.handle)
        {
            return Err(StartupError::Authority);
        }
        handles[index] = actual.handle;
    }
    Ok(DriverCaps {
        ports: handles[0],
        window: handles[1],
        requests: handles[2],
        events: handles[3],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::{Context, Grant, encode};
    #[cfg(feature = "workspace-profile")]
    #[test]
    fn selected_network_actors_require_each_exact_measured_limit_and_keep_old_parsers() {
        for network_actor in [false, true] {
            let template = usize::from(network_actor);
            let specs: &[(u64, u8, u16)] = if network_actor {
                &[(1, 1, 7), (2, 2, 8), (3, 1, 7), (4, 2, 272), (5, 2, 8)]
            } else {
                &[(1, 7, 3), (2, 1, 7), (3, 2, 272), (4, 2, 8)]
            };
            let mut grants = [Grant {
                selector: 1,
                handle: 11,
                kind: 1,
                rights: 7,
            }; 5];
            for (i, (selector, kind, rights)) in specs.iter().copied().enumerate() {
                grants[i] = Grant {
                    selector,
                    handle: 11 + i as u64,
                    kind,
                    rights,
                };
            }
            let grants = &grants[..specs.len()];
            let context = Context {
                epoch: 805,
                incarnation: 1,
                process: 3,
                limits: ev_userspace_contract::root_v5::resources::JOB_TEMPLATE_LIMITS[template],
                manifest: [1; 32],
                authority: [2; 32],
            };
            let selected = |bytes: &[u8]| {
                if network_actor {
                    network_m8(bytes).map(|_| ())
                } else {
                    driver_m8(bytes).map(|_| ())
                }
            };
            let legacy = |bytes: &[u8]| {
                if network_actor {
                    network(bytes).map(|_| ())
                } else {
                    driver(bytes).map(|_| ())
                }
            };
            assert_eq!(selected(&encode(context, grants).unwrap()), Ok(()));
            for field in 0..4 {
                let mut wrong = context;
                wrong.limits[field] += 1;
                assert_eq!(
                    selected(&encode(wrong, grants).unwrap()),
                    Err(StartupError::Authority)
                );
            }
            let old = Context {
                limits: if network_actor {
                    [16384, 64, 1, 1]
                } else {
                    [16384, 32, 1, 1]
                },
                ..context
            };
            let old_bytes = encode(old, grants).unwrap();
            assert_eq!(legacy(&old_bytes), Ok(()));
            assert_eq!(selected(&old_bytes), Err(StartupError::Authority));
            let mut wrong = [Grant {
                selector: 1,
                handle: 11,
                kind: 1,
                rights: 7,
            }; 5];
            wrong[..grants.len()].copy_from_slice(grants);
            wrong[1].handle = wrong[0].handle;
            assert_eq!(
                selected(&encode(context, &wrong[..grants.len()]).unwrap()),
                Err(StartupError::Authority)
            );
        }
    }

    #[test]
    fn driver_roles_refuse_aliases_extra_authority_and_missing_bindings() {
        let context = Context {
            epoch: 1,
            incarnation: 2,
            process: 3,
            limits: [4096, 32, 1, 1],
            manifest: [1; 32],
            authority: [2; 32],
        };
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
                kind: 1,
                rights: 7,
            },
            Grant {
                selector: 3,
                handle: 13,
                kind: 2,
                rights: 272,
            },
            Grant {
                selector: 4,
                handle: 14,
                kind: 2,
                rights: 8,
            },
        ];
        let encoded = encode(context, &grants).unwrap();
        assert_eq!(driver(&encoded).unwrap().requests, 13);
        for (index, replacement) in [
            (
                0,
                Grant {
                    rights: 1,
                    ..grants[0]
                },
            ),
            (
                1,
                Grant {
                    rights: 3,
                    ..grants[1]
                },
            ),
            (
                2,
                Grant {
                    rights: 24,
                    ..grants[2]
                },
            ),
            (
                3,
                Grant {
                    handle: 13,
                    ..grants[3]
                },
            ),
        ] {
            let mut bad = grants;
            bad[index] = replacement;
            assert_eq!(
                driver(&encode(context, &bad).unwrap()),
                Err(StartupError::Authority)
            );
        }
        assert_eq!(
            driver(&encode(context, &grants[..3]).unwrap()),
            Err(StartupError::Authority)
        );
    }
    #[test]
    fn protocol_service_has_two_distinct_windows_and_no_device_ports() {
        let context = Context {
            epoch: 1,
            incarnation: 2,
            process: 3,
            limits: [4096, 32, 1, 1],
            manifest: [1; 32],
            authority: [2; 32],
        };
        let mut grants = [
            Grant {
                selector: 1,
                handle: 11,
                kind: 1,
                rights: 7,
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
                kind: 1,
                rights: 7,
            },
            Grant {
                selector: 4,
                handle: 14,
                kind: 2,
                rights: 272,
            },
            Grant {
                selector: 5,
                handle: 15,
                kind: 2,
                rights: 8,
            },
        ];
        assert_eq!(
            network(&encode(context, &grants).unwrap())
                .unwrap()
                .incarnation,
            2
        );
        grants[2].handle = grants[0].handle;
        assert_eq!(
            network(&encode(context, &grants).unwrap()),
            Err(StartupError::Authority)
        );
        grants[2].handle = 13;
        grants[0].kind = 7;
        grants[0].rights = 3;
        assert_eq!(
            network(&encode(context, &grants).unwrap()),
            Err(StartupError::Authority)
        );
        assert_eq!(
            network(&encode(context, &grants[..4]).unwrap()),
            Err(StartupError::Authority)
        );
    }
}
