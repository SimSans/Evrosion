//! Explicit negative fixture: real denied App calls before normal Note startup.
#![forbid(unsafe_code)]
use ev_userspace_contract::{Bootstrap, syscall};
use ev_userspace_runtime as rt;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bootstrap,
    Clock,
    Denial,
}

/// Checks actual App-side canonical denial replies. A final runner must join
/// the actual protected sender/image, grants and Core denial/PIO observations;
/// this return value alone is not a successful VM authority test.
pub fn app_denials(boot: &Bootstrap<'_>, stop: u64) -> Result<u8, Error> {
    if boot.grants().count() != 7 || boot.grants().any(|g| g.kind == 7) {
        return Err(Error::Bootstrap);
    }
    let surface = boot
        .find(1)
        .filter(|g| g.kind == 1 && g.rights == 7)
        .ok_or(Error::Bootstrap)?
        .handle;
    let window = boot
        .find(5)
        .filter(|g| g.kind == 1 && g.rights == 7)
        .ok_or(Error::Bootstrap)?
        .handle;
    if surface == window {
        return Err(Error::Bootstrap);
    }
    let now = rt::call4(syscall::MONOTONIC, 0, 0, 0, 0);
    if now.status != 0 || now.capability != 0 || now.serial != 0 {
        return Err(Error::Clock);
    }
    let cut = rt::execution::deadline(stop, now.value, 512).map_err(|_| Error::Clock)?;
    for [operation, a, b, c, d] in [
        [syscall::PORT_INPUT, surface, 0x300, 1, 0],
        [syscall::PORT_OUTPUT, surface, 0x300, 1, 0],
        [
            syscall::RPC_CALL,
            window,
            u64::from_le_bytes(*b"S\x01\x05\0\x01\0\0\0"),
            cut,
            0,
        ],
        [syscall::NETWORK_RETIREMENT, 0, surface, window, cut],
        [syscall::PORT_INPUT_BYTES4, surface, 0x310, cut, 0],
        [syscall::PORT_OUTPUT_BYTES4, surface, 0x310, cut, 0x12345678],
    ] {
        let result = rt::call4(operation, a, b, c, d);
        if result.status != 1 || result.value != 0 || result.capability != 0 || result.serial != 0 {
            return Err(Error::Denial);
        }
    }
    Ok(6)
}

/// Explicit authenticated Root control activates CPU-only hostile work in the
/// existing App process. Real timer preemption and unchanged quotas contain it.
pub fn abusive_cpu() -> ! {
    let mut v = 1u64;
    loop {
        v = v.wrapping_mul(6364136223846793005).wrapping_add(1);
        core::hint::black_box(v);
    }
}
