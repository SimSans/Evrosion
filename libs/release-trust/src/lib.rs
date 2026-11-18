//! Bounded release-trust mechanisms, not capability or executable admission.
//! Signature syntax, independently provisioned authority, freshness, durable
//! replay state and loaded-image ownership remain distinct obligations.
#![no_std]
#![forbid(unsafe_code)]

// The current saved user context covers legacy x87/SSE, not AVX. Prevent the
// dependency's automatic AVX backend from silently exceeding that ISA contract.
#[cfg(all(target_os = "none", not(curve25519_dalek_backend = "serial")))]
compile_error!("bare-metal release verification requires the pinned serial curve backend");

pub mod signature;

pub mod checkpoint;
pub mod metadata;
pub mod verifier;

#[cfg(test)]
mod tests;
