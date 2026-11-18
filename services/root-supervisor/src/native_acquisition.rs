//! Root-owned durable acquisition coordination. Stored/signature-checked bytes
//! are distinct from executable admission, active state and KnownGood health.
//! The runtime temporal/publication adapter remains a separate required gate.
#![forbid(unsafe_code)]
pub const MAX_ROOT_MATERIALS: usize = 8;
pub const CHECKPOINT_BYTES: usize = 4096;
use ev_content_store::Object;
use sha2::{Digest, Sha256};
mod binding;
/// Canonical syntax only. Decoding a record never creates trusted/open state.
pub mod codec;
mod cold;
mod commit;
mod decision;
mod health;
mod preparation;
mod selection;
pub use binding::AuthorizationBinding;
pub use commit::Commit;
pub use decision::{Decision, Material, QualifiedClock, Remote};
pub use health::KnownGoodDecision;
pub use preparation::Preparation;
pub use selection::SelectionDecision;
mod stream;
pub use codec::{Authorization, Content};
pub use cold::{Buffers, Cold, LINK_BUFFER, ROOT_BUFFER, TARGET_BUFFER};
pub use stream::{Failure, Publication, Put, Read, Rejected, Snapshot, Store, Stored};
pub const HELLO_APP: [u8; 16] = [
    0x62, 0xc0, 0x76, 0x7e, 0x6c, 0x18, 0x45, 0x9c, 0x91, 0xe6, 0xeb, 0x8b, 0x94, 0x89, 0x58, 0xf2,
];
pub const ROM_ROOT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tools/m6/fixtures/development-root.bin"
));
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Checkpoint,
    Root,
    Metadata,
    Candidate,
    Phase,
    Capacity,
    Clock,
    Time,
    Unprovisioned,
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub fn binding() -> ev_release_trust::metadata::Binding {
    ev_release_trust::metadata::Binding {
        namespace: digest(b"evrosion.DEVELOPMENT.download-authority.v1\0"),
        channel: digest(b"development\0"),
        platform: digest(b"evrosion.x86_64.vm.root-v4.app-v1\0"),
    }
}
pub fn logical_target_name() -> [u8; 32] {
    mod anchor {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/m6/fixtures/development-target.rs"
        ));
    }
    anchor::HELLO_TARGET_NAME
}
#[cfg(test)]
pub(crate) mod tests;
