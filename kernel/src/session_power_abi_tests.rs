use super::*;
use ev_userspace_contract::syscall;
#[test]
fn optional_readiness_query_is_strict_metadata_and_preserves_old_info_shapes() {
    let mut f = UserContext::ZERO;
    f.registers[14] = syscall::SESSION_POWER_INFO;
    f.registers[8] = syscall::SESSION_POWER_READY_QUERY;
    f.registers[9] = 5;
    f.registers[11] = 9;
    f.registers[5] = 17 | (1 << 41);
    assert_eq!(
        decode(&f),
        Ok(Call::SessionPowerReady {
            nonce: 5,
            frame: 9,
            input: 17 | (1 << 41)
        })
    );
    for (reg, value) in [
        (9, 0),
        (9, u64::MAX),
        (11, 0),
        (11, u64::MAX),
        (5, u32::MAX as u64),
        (5, 1 << 43),
        (8, 3),
    ] {
        let mut bad = f;
        bad.registers[reg] = value;
        assert!(decode(&bad).is_err());
    }
    for query in [0, 1] {
        let mut bad = f;
        bad.registers[8] = query;
        assert!(decode(&bad).is_err());
    }
}
#[test]
fn negotiation_and_control_preserve_full_handles_and_reject_reserved_shapes() {
    let mut f = UserContext::ZERO;
    f.registers[14] = syscall::SESSION_POWER_INFO;
    assert_eq!(decode(&f), Ok(Call::SessionPowerInfo { restart: false }));
    f.registers[8] = 1;
    assert_eq!(decode(&f), Ok(Call::SessionPowerInfo { restart: true }));
    f.registers[8] = 0;
    for (reg, value) in [(8, 2), (9, 1), (11, 1), (5, 1)] {
        f.registers[reg] = value;
        assert!(decode(&f).is_err());
        f.registers[reg] = 0;
    }
    for operation in 0..=2 {
        f.registers[14] = syscall::SESSION_POWER;
        f.registers[8] = operation;
        f.registers[9] = 0x100000002;
        f.registers[11] = 0x200000003;
        f.registers[5] = 12345;
        assert_eq!(
            decode(&f),
            Ok(Call::SessionPower {
                operation,
                block: Handle(0x100000002),
                nic: Handle(0x200000003),
                extra: 12345
            })
        );
        for (reg, value) in [
            (8, 3),
            (9, 0),
            (11, 0),
            (11, 0x100000002),
            (5, 0),
            (5, u64::MAX),
        ] {
            let mut invalid = f;
            invalid.registers[reg] = value;
            assert!(decode(&invalid).is_err());
        }
    }
}
#[test]
fn every_power_reply_clears_old_extra_and_capability_on_success_and_error() {
    for status in [0, 1, 2, 3, 4] {
        let mut f = UserContext::ZERO;
        f.registers[5] = u64::MAX;
        f.registers[11] = 1234;
        reply_session_power(&mut f, status, 77);
        assert_eq!(
            (
                f.registers[14],
                f.registers[9],
                f.registers[11],
                f.registers[5]
            ),
            (status, if status == 0 { 77 } else { 0 }, 0, 0)
        );
    }
}
