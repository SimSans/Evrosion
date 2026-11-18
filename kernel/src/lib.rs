//! Portable, Internal kernel mechanisms; hardware entry stays in the binary.
#![no_std]
#![deny(unsafe_code)]
#[cfg(test)]
extern crate self as ev_kernel;
#[cfg(test)]
#[path = "native_runtime/dynamic/policy_tests.rs"]
mod dynamic_mapping_tests;
#[cfg(all(test, feature = "test-m6-network-negative"))]
#[path = "desktop_runtime/network_negative/returned.rs"]
mod negative_return_tests;

pub mod acpi;
pub mod allocation;
pub mod bootstrap_binding;
pub mod bootstrap_manifest;
pub mod cap_rpc;
pub mod capability;
pub mod custodian;
pub mod display;
pub mod display_plan;
pub mod display_walk;
pub mod dynamic_image;
pub mod events;
pub mod exception;
pub mod executable;
pub mod fault;
pub mod incarnation;
pub mod io_ports;
pub mod ipc;
pub mod job_info;
pub mod live_grant;
pub mod loaded_image;
#[cfg(feature = "workspace-authority")]
pub mod managed_send;
pub mod mapping;
pub mod memory;
pub mod memory_extent;
pub mod memory_object;
pub mod mutex;
pub mod restart;
pub mod rpc;
pub mod scheduler;
pub mod service;
pub mod surface_layout;
pub mod time;
pub mod user;
pub mod user_context;
pub mod wait_queue;

// Additive Root-only startup ABI; ordinary service bootstrap remains v1.
pub mod root_binding_v2;
pub mod root_factory_v2;
pub mod root_manifest_v2;
pub mod root_manifest_v4;
#[cfg(feature = "workspace-authority")]
pub mod root_manifest_v5;
pub mod root_producer_v2;
pub mod root_producer_v4;
#[cfg(feature = "workspace-authority")]
pub mod root_producer_v5;
mod root_selection;
#[cfg(test)]
mod root_v4_tests;
#[cfg(all(test, feature = "workspace-authority"))]
mod root_v5_tests;
#[cfg(feature = "workspace-authority")]
pub mod session_power;
pub mod startup_record;
pub mod startup_trace;
