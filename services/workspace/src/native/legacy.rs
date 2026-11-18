//! One actual existing LegacyFileIo508 window + LegacyFileBlock role2 owner.
//! The exact safe typed I/O core is shared with the feature-enabled model tests.
use super::window::Window;
use ev_block_service::store_io::DesktopEndpoint;
use ev_workspace_service::{
    legacy::{OriginalCreation, Owner},
    legacy_device::Device,
};

pub type Backend = Owner<Device<DesktopEndpoint, Window>>;
pub fn open(endpoint: u64) -> Backend {
    let transport = DesktopEndpoint::for_session_transactions(endpoint)
        .unwrap_or_else(|| ev_userspace_runtime::exit(1260));
    let device = Device::new(transport, Window::at(508, 1))
        .unwrap_or_else(|| ev_userspace_runtime::exit(1261));
    Owner::new(device, OriginalCreation::reference_desktop())
}
