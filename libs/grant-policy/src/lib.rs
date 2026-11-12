//! Bounded durable READ policy publication and cold activation checks.
//!
//! The trusted integration supplies explicit consent, the sole scoped Store
//! device owner and actual subject/resource projections. This bridge persists
//! policy, never runtime handles. It grants no capability merely by parsing a
//! record; real fresh managed delegation remains the handoff's responsibility.
//! The separate consent parser proves complete syntax, not trusted presentation
//! or input provenance. No application/runtime/VM acceptance follows from linking.
#![no_std]
#![forbid(unsafe_code)]

pub mod consent;
pub mod policy;
pub use policy::{
    Eligible, Error, Expected, FILE_PERMISSION_REVISION, FreshReadHandoff, PolicyOwner, Prepared,
    Published, Rejected, RemintResult, Resolution, Scope,
};

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;
