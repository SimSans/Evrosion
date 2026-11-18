//! Construct stable Root state field-by-field. No whole Root/desktop aggregate
//! is moved through the32KiB guarded private stack.
use super::*;
use core::{
    mem::MaybeUninit,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
static CLAIMED: AtomicBool = AtomicBool::new(false);
static mut ROOT: MaybeUninit<Root<'static>> = MaybeUninit::uninit();
/// # Safety
/// Called once by the actual Root entry. Both records reference exact retained
/// readonly Kernel-admitted mappings; no event/user can invoke this initializer.
pub(super) unsafe fn initialize(
    bootstrap: FullGraph<'static>,
    catalogue: Catalogue<'static>,
    identity: Identity,
    bound: u64,
) -> &'static mut Root<'static> {
    require(!CLAIMED.swap(true, Ordering::AcqRel), 1650);
    let slot = ptr::addr_of_mut!(ROOT).cast::<Root<'static>>();
    // SAFETY: sole successful once claim; every disjoint field is initialized
    // before the first Root reference. No aggregate temporary or alias escapes.
    unsafe {
        ptr::addr_of_mut!((*slot).bootstrap).write(bootstrap);
        ptr::addr_of_mut!((*slot).catalogue).write(catalogue);
        ptr::addr_of_mut!((*slot).channels).write([0; 23]);
        ptr::addr_of_mut!((*slot).actors).write([None; 11]);
        ptr::addr_of_mut!((*slot).policy).write(None);
        ptr::addr_of_mut!((*slot).protected).write(Protected::new(identity));
        ptr::addr_of_mut!((*slot).workspace).write(Workspace::new());
        ptr::addr_of_mut!((*slot).input).write(Input::new());
        ptr::addr_of_mut!((*slot).owner).write(OwnerFlow::new());
        ptr::addr_of_mut!((*slot).inspector).write(inspector::Snapshot::new());
        ptr::addr_of_mut!((*slot).inspector_self).write(inspector_self::claim());
        ptr::addr_of_mut!((*slot).semantic).write(semantic::claim());
        ptr::addr_of_mut!((*slot).shutdown).write(shutdown::Controller::new());
        ptr::addr_of_mut!((*slot).private_data).write(app_data::State::new());
        ptr::addr_of_mut!((*slot).development).write(development::Controller::new());
        ptr::addr_of_mut!((*slot).recovery).write(recovery::State::new());
        ptr::addr_of_mut!((*slot).shell_gesture).write(None);
        ptr::addr_of_mut!((*slot).outbox).write(ev_workspace_root::outbox::Outbox::new());
        ptr::addr_of_mut!((*slot).next_control).write(0);
        ptr::addr_of_mut!((*slot).registration).write(0);
        ptr::addr_of_mut!((*slot).states).write([None; 4]);
        ptr::addr_of_mut!((*slot).leases).write([const { None }; 4]);
        ptr::addr_of_mut!((*slot).paused).write([None; 4]);
        ptr::addr_of_mut!((*slot).file_may_be_held).write([false; 4]);
        ptr::addr_of_mut!((*slot).grant).write(None);
        ptr::addr_of_mut!((*slot).next_release).write(0);
        ptr::addr_of_mut!((*slot).next_lease).write(0);
        ptr::addr_of_mut!((*slot).lease_rights).write([0; 4]);
        ptr::addr_of_mut!((*slot).closing).write([false; 4]);
        ptr::addr_of_mut!((*slot).relaunch).write([false; 4]);
        ptr::addr_of_mut!((*slot).scene_dirty).write(false);
        ptr::addr_of_mut!((*slot).status).write(b"Starting independently owned workspace actors");
        ptr::addr_of_mut!((*slot).last_refusal).write(None);
        ptr::addr_of_mut!((*slot).bound).write(bound);
        &mut *slot
    }
}
