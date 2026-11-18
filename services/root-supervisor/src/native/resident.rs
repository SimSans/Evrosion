//! Native resident Root and V4 Controller. No typed static reference exists: static bytes
//! have a bounded single initializer, then the actual startup/bank/window
//! lifetime supplies the sole Controller borrow until this Root exits.
use super::*;
#[path = "resident_slot.rs"]
pub(super) mod slot;
#[cfg(feature = "native-network")]
const WORDS: usize = core::mem::size_of::<Controller<'static>>().div_ceil(16);
#[cfg(feature = "native-network")]
static STORAGE: slot::Slot<WORDS> = slot::Slot::new();

/// # Safety
/// Exact admitted V4 Root startup, private .bss and named mappings remain owned
/// for this Root execution. Actual package and backend borrows supply 'a; no
/// reference is widened to static. Called once, before any child/lifecycle pump.
#[cfg(feature = "native-network")]
#[allow(clippy::too_many_arguments)] // One-claim in-place initialization retains all named owners.
#[inline(never)]
pub(super) unsafe fn initialize<'a>(
    packages: Packages<'a>,
    backend: storage::Backend<'a>,
    record: u64,
    endpoint: u64,
    creator: u64,
    context: ev_userspace_contract::Context,
    mode: abi::catalogue::BootMode,
    bound: u64,
) -> &'a mut Controller<'a> {
    let mut claim = STORAGE
        .claim::<Controller<'a>>()
        .unwrap_or_else(|_| fail(1025));
    let p = claim.pointer();
    // SAFETY: same retained private Root lifetime, before child/IO work.
    let updates = unsafe { update_runtime::owner(&backend) };
    // SAFETY: each distinct field is initialized in place before creating any
    // Controller reference. Constructors do not publish loans/children or pump
    // lifecycle work. A failure leaves the one claim permanently unavailable;
    // no uninitialized T is read or dropped. Kernel owns stopped-frame erasure.
    unsafe {
        crate::resident_initialize_fields!(p, Controller<'a>;
            #[cfg(feature="native-owner-ui")]
            connection: connection_runtime::Owner::new(),
            packages: packages,
            images: image_runtime::owner(record, creator),
            network: ev_root_supervisor::native_network::State::new(),
            network_recovery: network_recovery::Recovery::new(),
            network_probe: network_probe::Probe::new(),
            network_client: network_runtime::client(record, endpoint),
            network_random: vm_entropy::Random::unavailable(
            ev_time_contract::Domain::new(context.epoch).unwrap_or_else(|_| fail(1022)),
        ),
            network_clock: vm_rtc::Source::new(),
            network_time: time_runtime::Time::new(),
            updates: updates,
            network_transfer: ev_root_supervisor::native_network::transfer::Transfer::new(),
            network_report: None,
            network_diagnostic: None,
            network_diagnostic_reported: false,
            network_failure: None,
            network_failure_reported: false,
            network_report_failed: false,
            state: State::new_downloaded_v2(backend),
            note_window: storage::NoteWindow::new(record),
            note_reply: None,
            delivery_failure: None,
            lines: Lines::new(),
            transition: None,
            running: None,
            #[cfg(feature="document-workflow")]
            focused_input_minor:0,
            preparing: None,
            starting: false,
            app_settled: false,
            command_after_start: None,
            input_bytes: 0,
            report: None,
            report_frame: None,
            report_serial: 0,
            finish_after_report: false,
            boot_launch_pending: false,
            diagnostics: diagnostics::Diagnostics::new(),
            system: system_runtime::System::new(mode, bound),
            owner_flow: owner_runtime::Owner::new(),
        );
        // All actual fields above initialized exactly once; raw pointer is not
        // used after this sole scoped-reference handoff.
        claim.initialized()
    }
}

const ROOT_WORDS: usize = core::mem::size_of::<Root<'static>>().div_ceil(16);
static ROOT_STORAGE: slot::Slot<ROOT_WORDS> = slot::Slot::new();
/// # Safety
/// The exact immutable selected native startup/catalogue mappings remain owned for this Root
/// execution. Called once before the first child/pump. Each field borrows those
/// real mappings or owns independent private state; no field refers into Root.
#[inline(never)]
pub(super) unsafe fn initialize_root<'a>(
    bootstrap: profile::NativeFullGraph<'a>,
    catalogue: Catalogue<'a>,
    bound: u64,
    epoch: [u8; 16],
    owner: UserId,
) -> &'a mut Root<'a> {
    let mut claim = ROOT_STORAGE
        .claim::<Root<'a>>()
        .unwrap_or_else(|_| fail(1051));
    let p = claim.pointer();
    // SAFETY: one permanent aligned private claim; every distinct field is
    // initialized before the sole reference exists. Failure exposes no Root,
    // and stopped-frame erasure remains the ordinary Kernel owner's duty.
    unsafe {
        crate::resident_initialize_fields!(p, Root<'a>;
            delivery: core::cell::RefCell::new(delivery::State::new()),
            bootstrap: Bootstrap::Native(bootstrap),
            catalogue: catalogue,
            channels: [0; profile::CHANNEL_SLOTS],
            actors: [None; COUNT],
            bound: bound,
            app_epoch: 0,
            shell_epoch: 1,
            request: 0,
            pending: None,
            picker: Picker::new(PickerEpoch::new(epoch).unwrap(), 131072).unwrap(),
            owner: owner,
            session: SessionId::new(epoch).unwrap(),
            boot: BootEpoch::new(epoch).unwrap(),
            last_cancel: false,
            hide_pending: false,
            launch_pending: false,
            app_notified: false,
            input_epoch: 1,
            shell_recovering: false,
            native: None,
            owned_launch: false,
        );
        claim.initialized()
    }
}
