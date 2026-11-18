//! Native package ownership and the explicit native profile of the shared
//! protected desktop executor. Package bytes never become ambient authority.
pub(crate) mod backing;
#[cfg(feature = "test-m6-network")]
pub(crate) mod dynamic;
pub(crate) mod image;
pub(crate) mod profile;

use crate::desktop_runtime::{CommonAssets, Observation};
use backing::NativeBacking;

pub(crate) struct Assets {
    pub common: CommonAssets<'static>,
    pub app_b: (&'static [u8], [u8; 32]),
    pub bad_shell: (&'static [u8], [u8; 32]),
    pub packages: [&'static [u8]; 2],
}
pub(crate) struct Proof {
    pub graph: crate::desktop_runtime::Proof,
    #[cfg(feature = "test-m6-network-negative")]
    pub network_no_ack_returns: u64,
    pub common_prefix: bool,
    pub app_starts: [u64; 2],
    pub app_stops: [u64; 2],
    pub app_reaps: [u64; 2],
    pub last_process: [u64; 2],
    pub last_thread: [u64; 2],
    pub package_pages: [u64; 2],
    pub bank_maps: u64,
    pub bank_detaches: u64,
    pub bank_reclaimed: u64,
    pub root_exit: bool,
    pub readonly_rejections: u64,
}
pub(crate) struct State<'a> {
    pub backing: &'a mut NativeBacking,
    pub image_objects: [usize; 2],
    pub image_shas: [[u8; 32]; 2],
    pub bad_shell_object: usize,
    pub bad_shell_sha: [u8; 32],
    pub boot_mode: ev_userspace_contract::root_v2::native::catalogue::BootMode,
    pub started_mappings: u64,
    pub common_prefix: bool,
    pub root_image_sha256: [u8; 32],
    pub root_manifest_sha256: [u8; 32],
    pub self_identity_queries: u64,
    pub app_starts: [u64; 2],
    pub app_stops: [u64; 2],
    pub app_reaps: [u64; 2],
    pub last_process: [u64; 2],
    pub last_thread: [u64; 2],
    pub finish_requested: bool,
    pub root_exited: bool,
    pub bank_maps: u64,
    pub bank_detaches: u64,
    pub readonly_rejections: u64,
    pub shell_starts: u64,
    pub readonly_denial: Option<(ev_kernel::scheduler::ProcessId, ev_kernel::rpc::CallId)>,
    pub report: ev_userspace_contract::root_v2::native::report::Decoder,
    pub report_origin: Option<(u32, u64, u64, [u8; 32])>,
    pub report_error: bool,
    pub diagnostics: ev_diagnostics::framing::Decoder,
    pub diagnostic_origin: Option<(u64, u64)>,
    pub diagnostic_error: bool,
    pub diagnostic_queries: u64,
    /// Last actual syscall trap for each retained actor slot; diagnostics only.
    pub last_syscall: [Option<u64>; profile::SLOTS],
    pub profile: profile::Profile,
}
impl State<'_> {
    pub fn app(&self, object: usize) -> Option<usize> {
        self.image_objects.iter().position(|id| *id == object)
    }
}
/// # Safety
/// Same sole restored-CR3 owner as the desktop world; assets are actual retained
/// measured boot inputs. Root completion requests never replace real teardown.
pub(crate) unsafe fn prove(
    offset: u64,
    frames: &mut ev_kernel::memory::BootstrapFrames,
    framebuffer: ev_boot_contract::Framebuffer,
    assets: &Assets,
    observe: impl FnMut(Observation),
) -> Proof {
    // SAFETY: shared checked executor retains all Native banks/image owners.
    unsafe { crate::desktop_runtime::prove_native(offset, frames, framebuffer, assets, observe) }
}
