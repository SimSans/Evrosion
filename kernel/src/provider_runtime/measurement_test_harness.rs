//! Hosts the exact active recorder without linking the freestanding Kernel bin.
//! The binary-private DTOs below carry data only; no recorder behavior is copied.
//! Ordinary target checks still compile the recorder against its real callers.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub process: u64,
    pub thread: u64,
    pub image_sha256: [u8; 32],
}

pub struct CompletedCall {
    pub nonce: u64,
    pub endpoint: u64,
    pub send_handle: u64,
    pub caller: Identity,
    pub callee: Identity,
    pub request: u64,
    pub reply: u64,
}

#[path = "measurement.rs"]
pub mod measurement;
