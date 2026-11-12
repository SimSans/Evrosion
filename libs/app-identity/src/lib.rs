//! Canonical stable application registry key. A claimed key grants no ownership,
//! publisher/update authority, private data, process identity or capability.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppId([u8; 16]);
impl AppId {
    pub fn new(bytes: [u8; 16]) -> Option<Self> {
        bytes.iter().any(|byte| *byte != 0).then_some(Self(bytes))
    }
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}
