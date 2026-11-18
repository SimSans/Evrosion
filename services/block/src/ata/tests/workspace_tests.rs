use super::*;
use crate::workspace;
#[cfg(feature = "pio-words256")]
#[path = "words256_tests.rs"]
mod words256_tests;
fn workspace_identity() -> [u8; 512] {
    let mut bytes = identify_bytes();
    bytes[120..122].copy_from_slice(&(workspace::DISK_SECTORS as u16).to_le_bytes());
    bytes[122..124].copy_from_slice(&((workspace::DISK_SECTORS >> 16) as u16).to_le_bytes());
    for (i, byte) in workspace::SERIAL.iter().enumerate() {
        bytes[20 + (i ^ 1)] = *byte;
    }
    bytes
}
#[test]
fn new_identity_geometry_never_widen_the_legacy_parser_or_constructor() {
    let legacy = identify_bytes();
    let current = workspace_identity();
    assert!(parse_identify(&legacy).is_ok());
    assert_eq!(parse_workspace_identify(&legacy), Err(Error::Identity));
    assert_eq!(parse_identify(&current), Err(Error::Identity));
    assert_eq!(
        parse_workspace_identify(&current),
        Ok(Info {
            sectors: workspace::DISK_SECTORS,
            sector_bytes: 512
        })
    );
    let mut bad = current;
    bad[120] ^= 1;
    assert_eq!(parse_workspace_identify(&bad), Err(Error::Geometry));
    let mut bus = Bus::new();
    bus.identify = current;
    let mut old = AtaPio::new(bus);
    assert_eq!(old.identify(100_000).unwrap_err().error, Error::Identity);
}
#[test]
fn workspace_ata_commands_reach_both_real_region_boundaries_with_exact_readback() {
    for physical in [workspace::WORKSPACE_START, workspace::WORKSPACE_END - 1] {
        let mut bus = Bus::new();
        bus.identify = workspace_identity();
        bus.lba_base = physical;
        let mut disk = AtaPio::new_workspace(bus);
        disk.reset(100_000).unwrap();
        disk.identify(100_000).unwrap();
        disk.write_sector(physical, &RECORD, 100_000).unwrap();
        disk.flush(100_000).unwrap();
        let mut bytes = [0; 512];
        disk.read_sector(physical, &mut bytes, 100_000).unwrap();
        assert_eq!(bytes, RECORD);
        let calls = disk.io.trace.len();
        assert_eq!(
            disk.read_sector(workspace::DISK_SECTORS, &mut bytes, 100_000)
                .unwrap_err()
                .error,
            Error::Bounds
        );
        assert_eq!(disk.io.trace.len(), calls);
        assert_eq!(disk.io.disk[0], RECORD);
    }
}
