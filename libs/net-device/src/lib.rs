//! Bounded helpers for a separately authorized userspace network driver.
//!
//! These helpers neither mint port authority nor establish hardware quiescence.
//! The NE2000 layout targets the reviewed QEMU ISA implementation; it is not a
//! contract for arbitrary physical devices or other DMA-capable NIC models.
#![no_std]
#![forbid(unsafe_code)]

pub mod ne2000;
pub mod packet;

#[cfg(test)]
mod tests;
