//! Portable, Internal kernel mechanisms; hardware entry stays in the binary.
#![no_std]
#![deny(unsafe_code)]

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
pub mod root_producer_v2;
mod root_selection;
pub mod startup_record;
