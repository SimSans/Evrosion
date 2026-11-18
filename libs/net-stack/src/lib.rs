//! Internal bounded userspace stack adapter. Network authority, trusted entropy,
//! TLS and update verification remain separate actual service responsibilities.
#![no_std]
#![forbid(unsafe_code)]

/// Pinned implementation identity, not a Stable networking ABI.
pub const STACK_VERSION: &str = "smoltcp 0.14.0";

pub mod device;
pub mod stack;
