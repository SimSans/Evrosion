//! Pure preflight shared by actual volatile HAL reads and adversarial tests.
//! These integers are never allocation/mapping authority or a hardware witness.
use ev_kernel::mapping::{ADDRESS_MASK, NO_EXECUTE, PRESENT, WRITABLE};
use ev_userspace_contract::root_v4::dynamic as abi;
const USER: u64 = 4;
const AD: u64 = (1 << 5) | (1 << 6);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Window {
    Writer,
    Reader(usize),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Read,
    Foreign,
}
impl Window {
    pub fn first(self) -> Result<usize, Error> {
        match self {
            Self::Writer => Ok(abi::STAGING_FIRST),
            Self::Reader(i) => abi::READONLY_FIRST.get(i).copied().ok_or(Error::Bounds),
        }
    }
}
pub fn empty(
    mut read: impl FnMut(usize) -> Result<u64, Error>,
    window: Window,
) -> Result<(), Error> {
    let first = window.first()?;
    for i in first - 1..=first + abi::WINDOW_PAGES {
        if read(i)? != 0 {
            return Err(Error::Foreign);
        }
    }
    Ok(())
}
pub fn retained(
    mut read: impl FnMut(usize) -> Result<u64, Error>,
    window: Window,
    physical: u64,
    pages: usize,
    installed: bool,
) -> Result<(), Error> {
    let first = window.first()?;
    if pages == 0
        || pages > abi::WINDOW_PAGES
        || physical == 0
        || physical & ADDRESS_MASK != physical
        || physical
            .checked_add((pages - 1) as u64 * 4096)
            .is_none_or(|n| n & ADDRESS_MASK != n)
    {
        return Err(Error::Bounds);
    }
    let flags = PRESENT
        | USER
        | NO_EXECUTE
        | if window == Window::Writer {
            WRITABLE
        } else {
            0
        };
    for i in first - 1..=first + abi::WINDOW_PAGES {
        let expected = if (first..first + pages).contains(&i) {
            (physical + (i - first) as u64 * 4096) | flags
        } else {
            0
        };
        let raw = read(i)?;
        let actual = if expected == 0 { raw } else { raw & !AD };
        if actual != expected && (installed || raw != 0) {
            return Err(Error::Foreign);
        }
    }
    Ok(())
}
