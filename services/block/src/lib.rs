//! Internal userspace ATA PIO reference backend; application storage remains
//! behind E-010 stable File/Object authority and userspace filesystem services.
#![no_std]
#![forbid(unsafe_code)]
pub mod ata;
#[cfg(feature = "test-generation-client")]
pub mod critical_progress;
#[cfg(feature = "test-store-client")]
pub mod desktop;
#[cfg(feature = "test-owner-client")]
pub mod owner_console;
#[cfg(feature = "test-store-client")]
pub mod store_io;
use ev_userspace_contract::Bootstrap;

pub const SECTOR_BYTES: usize = 512;
pub const DISK_SECTORS: u32 = 8192;
pub const SEED_LBA: u32 = 0;
pub const TEST_LBA: u32 = 1;
pub const PORT_BASE: u16 = 0x1e8;
pub const CONTROL_PORT: u16 = 0x3ee;
pub const SERIAL: [u8; 20] = *b"EVROSION-M3-PIO     ";
const fn pattern(multiplier: u8, offset: u8) -> [u8; SECTOR_BYTES] {
    let mut bytes = [0; SECTOR_BYTES];
    let mut i = 0;
    while i < bytes.len() {
        bytes[i] = (i as u8).wrapping_mul(multiplier).wrapping_add(offset);
        i += 1;
    }
    bytes
}
/// Immutable fixture bytes; no writable global driver state or buffer exists.
pub static SEED: [u8; SECTOR_BYTES] = pattern(17, 0x53);
pub static RECORD: [u8; SECTOR_BYTES] = pattern(29, 0xa7);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub ports: u64,
    pub read_only: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverCapabilities {
    pub ports: u64,
    pub buffer: u64,
    pub request: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientCapabilities {
    pub buffer: u64,
    pub request: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationCapabilities {
    pub buffer: u64,
    pub block: u64,
    pub job: u64,
    pub image_a: u64,
    pub image_b: u64,
    pub event_rx: u64,
    pub event_tx: u64,
    pub catalogue: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerCapabilities {
    pub generation: GenerationCapabilities,
    pub uart: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum StartupError {
    Limits,
    Bootstrap(ev_userspace_contract::Error),
    Count,
    Missing,
    Authority,
}
/// The kernel binds both roles to the same actual controller object. Numeric
/// handles alone do not prove object identity or a permitted port range.
pub fn startup(bytes: &[u8]) -> Result<Capabilities, StartupError> {
    let record = Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    if record.grants().count() != 2 {
        return Err(StartupError::Count);
    }
    let ports = record.find(1).ok_or(StartupError::Missing)?;
    let read_only = record.find(2).ok_or(StartupError::Missing)?;
    if ports.kind != 7 || ports.rights != 3 || read_only.kind != 7 || read_only.rights != 1 {
        return Err(StartupError::Authority);
    }
    Ok(Capabilities {
        ports: ports.handle,
        read_only: read_only.handle,
    })
}
/// Closed internal driver roles. The transport separately validates the actual
/// Memory identity, mapping lease and endpoint receiver binding.
pub fn driver_startup(bytes: &[u8]) -> Result<DriverCapabilities, StartupError> {
    let record = Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    if record.grants().count() != 3 {
        return Err(StartupError::Count);
    }
    let ports = record.find(1).ok_or(StartupError::Missing)?;
    let buffer = record.find(2).ok_or(StartupError::Missing)?;
    let request = record.find(3).ok_or(StartupError::Missing)?;
    if ports.kind != 7
        || ports.rights != 3
        || buffer.kind != 1
        || buffer.rights != 7
        || request.kind != 2
        || request.rights != 272
    {
        return Err(StartupError::Authority);
    }
    Ok(DriverCapabilities {
        ports: ports.handle,
        buffer: buffer.handle,
        request: request.handle,
    })
}
/// A block client has a prebound shared window and SEND authority, no raw port
/// capability. E-010 application File/Object service authority is unchanged.
pub fn client_startup(bytes: &[u8]) -> Result<ClientCapabilities, StartupError> {
    let record = Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    if record.grants().count() != 2 {
        return Err(StartupError::Count);
    }
    let buffer = record.find(1).ok_or(StartupError::Missing)?;
    let request = record.find(2).ok_or(StartupError::Missing)?;
    if buffer.kind != 1 || buffer.rights != 7 || request.kind != 2 || request.rights != 8 {
        return Err(StartupError::Authority);
    }
    Ok(ClientCapabilities {
        buffer: buffer.handle,
        request: request.handle,
    })
}
pub fn generation_startup(bytes: &[u8]) -> Result<GenerationCapabilities, StartupError> {
    let record = Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    if record.grants().count() != 8 {
        return Err(StartupError::Count);
    }
    let mut handles = [0; 8];
    for (index, (kind, rights)) in [
        (1, 231),
        (2, 8),
        (5, 256),
        (1, 1),
        (1, 1),
        (2, 272),
        (2, 232),
        (1, 5),
    ]
    .into_iter()
    .enumerate()
    {
        let grant = record.find(index as u64 + 1).ok_or(StartupError::Missing)?;
        if grant.kind != kind || grant.rights != rights {
            return Err(StartupError::Authority);
        }
        handles[index] = grant.handle;
    }
    Ok(GenerationCapabilities {
        buffer: handles[0],
        block: handles[1],
        job: handles[2],
        image_a: handles[3],
        image_b: handles[4],
        event_rx: handles[5],
        event_tx: handles[6],
        catalogue: handles[7],
    })
}
pub fn owner_startup(bytes: &[u8]) -> Result<OwnerCapabilities, StartupError> {
    let record = Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    if record.grants().count() != 8 {
        return Err(StartupError::Count);
    }
    let mut handles = [0; 8];
    for (index, (kind, rights)) in [
        (1, 231),
        (2, 8),
        (5, 256),
        (1, 1),
        (1, 1),
        (2, 504),
        (7, 3),
        (1, 5),
    ]
    .into_iter()
    .enumerate()
    {
        let grant = record.find(index as u64 + 1).ok_or(StartupError::Missing)?;
        if grant.kind != kind || grant.rights != rights {
            return Err(StartupError::Authority);
        }
        handles[index] = grant.handle;
    }
    Ok(OwnerCapabilities {
        generation: GenerationCapabilities {
            buffer: handles[0],
            block: handles[1],
            job: handles[2],
            image_a: handles[3],
            image_b: handles[4],
            event_rx: handles[5],
            event_tx: handles[5],
            catalogue: handles[7],
        },
        uart: handles[6],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::{Context, Grant, encode};
    fn record(grants: &[Grant]) -> [u8; ev_userspace_contract::SIZE] {
        encode(
            Context {
                epoch: 1,
                incarnation: 1,
                process: 1,
                limits: [1024, 32, 1, 1],
                manifest: [1; 32],
                authority: [2; 32],
            },
            grants,
        )
        .unwrap()
    }
    fn grants() -> [Grant; 2] {
        [
            Grant {
                selector: 1,
                handle: 256,
                kind: 7,
                rights: 3,
            },
            Grant {
                selector: 2,
                handle: 257,
                kind: 7,
                rights: 1,
            },
        ]
    }
    #[test]
    fn exact_two_controller_roles_are_required_without_io_or_extra_authority() {
        assert_eq!(
            startup(&record(&grants())),
            Ok(Capabilities {
                ports: 256,
                read_only: 257
            })
        );
        assert_eq!(startup(&record(&grants()[..1])), Err(StartupError::Count));
        for (index, rights) in [(0, 1), (0, 7), (1, 3), (1, 257)] {
            let mut g = grants();
            g[index].rights = rights;
            if let Ok(encoded) = encode(
                Context {
                    epoch: 1,
                    incarnation: 1,
                    process: 1,
                    limits: [1024, 32, 1, 1],
                    manifest: [1; 32],
                    authority: [2; 32],
                },
                &g,
            ) {
                assert!(startup(&encoded).is_err());
            }
        }
        let bytes = record(&grants());
        for n in 0..bytes.len() {
            assert!(startup(&bytes[..n]).is_err());
        }
    }
    #[test]
    fn host_runner_patterns_and_sector_boundary_are_exact_and_distinct() {
        assert_eq!(SEED.len(), 512);
        assert_eq!(RECORD.len(), 512);
        for i in 0..512 {
            assert_eq!(SEED[i], ((i * 17 + 0x53) & 255) as u8);
            assert_eq!(RECORD[i], ((i * 29 + 0xa7) & 255) as u8);
        }
        assert_ne!(SEED, RECORD);
        assert_eq!(SEED_LBA, 0);
        assert_eq!(TEST_LBA, 1);
        assert_eq!(DISK_SECTORS * 512, 4 * 1024 * 1024);
    }
    #[test]
    fn shared_driver_and_client_require_exact_closed_roles() {
        let driver = [
            Grant {
                selector: 1,
                handle: 256,
                kind: 7,
                rights: 3,
            },
            Grant {
                selector: 2,
                handle: 257,
                kind: 1,
                rights: 7,
            },
            Grant {
                selector: 3,
                handle: 258,
                kind: 2,
                rights: 272,
            },
        ];
        let client = [
            Grant {
                selector: 1,
                handle: 256,
                kind: 1,
                rights: 7,
            },
            Grant {
                selector: 2,
                handle: 257,
                kind: 2,
                rights: 8,
            },
        ];
        assert_eq!(
            driver_startup(&record(&driver)),
            Ok(DriverCapabilities {
                ports: 256,
                buffer: 257,
                request: 258
            })
        );
        assert_eq!(
            client_startup(&record(&client)),
            Ok(ClientCapabilities {
                buffer: 256,
                request: 257
            })
        );
        assert!(client_startup(&record(&driver)).is_err());
        assert!(driver_startup(&record(&client)).is_err());
        for i in 0..driver.len() {
            let mut wrong = record(&driver);
            wrong[ev_userspace_contract::HEADER + i * ev_userspace_contract::GRANT_BYTES + 16] = 0;
            assert!(driver_startup(&wrong).is_err());
            let mut wrong = driver;
            wrong[i].rights ^= 32;
            assert!(driver_startup(&record(&wrong)).is_err());
        }
        for i in 0..client.len() {
            let mut wrong = client;
            wrong[i].rights ^= 32;
            assert!(client_startup(&record(&wrong)).is_err());
            let mut wrong = record(&client);
            wrong[ev_userspace_contract::HEADER + i * ev_userspace_contract::GRANT_BYTES] += 4;
            assert!(client_startup(&wrong).is_err());
        }
        assert!(driver_startup(&record(&driver[..2])).is_err());
        assert!(client_startup(&record(&client[..1])).is_err());
    }
    #[test]
    fn generation_requires_exact_eight_capabilities_and_readonly_catalogue() {
        let grants = core::array::from_fn::<_, 8, _>(|i| {
            let (kind, rights) = [
                (1, 231),
                (2, 8),
                (5, 256),
                (1, 1),
                (1, 1),
                (2, 272),
                (2, 232),
                (1, 5),
            ][i];
            Grant {
                selector: i as u64 + 1,
                handle: 256 + i as u64,
                kind,
                rights,
            }
        });
        let caps = generation_startup(&record(&grants)).unwrap();
        assert_eq!(caps.catalogue, 263);
        assert_eq!(caps.job, 258);
        assert_eq!(caps.event_tx, 262);
        assert!(generation_startup(&record(&grants[..7])).is_err());
        for i in 0..8 {
            let mut wrong = grants;
            wrong[i].rights ^= 128;
            assert!(generation_startup(&record(&wrong)).is_err());
        }
        let mut writable = grants;
        writable[7].rights = 7;
        assert_eq!(
            generation_startup(&record(&writable)),
            Err(StartupError::Authority)
        );
        assert!(client_startup(&record(&grants)).is_err());
        assert!(driver_startup(&record(&grants)).is_err());
    }
    #[test]
    fn owner_merges_existing_event_authority_and_adds_only_scoped_uart() {
        let grants = core::array::from_fn::<_, 8, _>(|i| {
            let (kind, rights) = [
                (1, 231),
                (2, 8),
                (5, 256),
                (1, 1),
                (1, 1),
                (2, 504),
                (7, 3),
                (1, 5),
            ][i];
            Grant {
                selector: i as u64 + 1,
                handle: 256 + i as u64,
                kind,
                rights,
            }
        });
        let caps = owner_startup(&record(&grants)).unwrap();
        assert_eq!(caps.generation.event_rx, caps.generation.event_tx);
        assert_eq!(caps.uart, 262);
        assert_eq!(caps.generation.catalogue, 263);
        assert!(generation_startup(&record(&grants)).is_err());
        assert!(owner_startup(&record(&grants[..7])).is_err());
        let mut wrong = grants;
        wrong[5].rights = 376;
        assert!(owner_startup(&record(&wrong)).is_err());
        let mut wrong = grants;
        wrong[6].rights = 1;
        assert!(owner_startup(&record(&wrong)).is_err());
    }
}
