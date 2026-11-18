//! Safe trusted-shell policy reducers. Effects are UI/control requests, never
//! capability grants or proof of an authenticated input/widget boundary.
#![no_std]
#![forbid(unsafe_code)]
pub mod compositor_policy;
pub mod protocol;
pub mod shell_delivery;
pub mod shell_policy;
#[cfg(feature = "workspace-input")]
pub mod workspace_input;

#[cfg(feature = "native-owner-ui")]
pub mod owner_ui;
