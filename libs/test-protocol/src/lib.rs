#![no_std]

//! Internal M0 serial and QEMU exit conventions, shared by kernel and runner.

pub const VERSION: u32 = 1;
pub const ENTERED: &str = "Evrosion kernel entered.";
pub const PASS: &str = "EVROSION_M0_RESULT status=PASS code=0";
pub const FAIL: &str = "EVROSION_M0_RESULT status=FAIL code=1";
pub const QEMU_EXIT_PORT: u16 = 0xf4;
pub const QEMU_PASS_VALUE: u32 = 0x10;
pub const QEMU_FAIL_VALUE: u32 = 0x11;
pub const QEMU_PASS_STATUS: i32 = ((QEMU_PASS_VALUE << 1) | 1) as i32;
pub const QEMU_FAIL_STATUS: i32 = ((QEMU_FAIL_VALUE << 1) | 1) as i32;
