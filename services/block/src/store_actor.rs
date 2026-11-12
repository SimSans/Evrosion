//! Ordinary measured CPL3 journal fixture. No admission, health report or
//! KnownGood transition is fabricated; A remains unresolved Pending metadata.
use super::{require, rpc_actor::Window};
use ev_block_service::store_io::{Endpoint, Mutations, StoreRegion, Window as _, Wire};
use ev_store::{BootPolicy, GenerationId, GenerationManifest, ObjectId, OperationId, Store};
use ev_userspace_contract::{
    block::{Request as BlockRequest, Response},
    store_test::{Completion, Control, Mode},
};
use ev_userspace_runtime::{self as rt, SyncEndpoint};

const OWNER_A: &[u8] = b"owner-data-A";
const OWNER_B: &[u8] = b"owner-data-B";
/// Deliberately unresolved fixture references. Persisting them is not trusted
/// cohort resolution, measured execution, health or authentication evidence.
fn pending_a() -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [0x11; 32],
        supervisor_image: [0x22; 32],
        abi: ev_userspace_contract::ABI,
        health_contract: [0x33; 32],
        health_version: 1,
        required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
    }
}
struct CrashAt {
    mutation: u64,
}
impl Mutations for CrashAt {
    fn completed(&mut self, count: u64) {
        if self.mutation != 0 && count == self.mutation {
            // SAFETY: separately measured negative fixture. This is an actual
            // CPL3 #UD after the selected completed reply and before any next
            // block request; it cannot alter kernel privilege or disk bytes.
            unsafe {
                core::arch::asm!("ud2", options(noreturn));
            }
        }
    }
}
type Device = StoreRegion<Endpoint, Window, CrashAt>;
type Failure = ev_store::Error<ev_block_service::store_io::Error<rt::SyncError>>;
fn failed(stage: u64, error: Failure) -> ! {
    let reason = match error {
        ev_store::Error::Io(ev_block_service::store_io::Error::Transport(
            rt::SyncError::Status(s),
        )) => 0x1000 | s,
        ev_store::Error::Io(_) => 1,
        ev_store::Error::Corrupt => 2,
        ev_store::Error::NotBlank => 3,
        ev_store::Error::Unformatted => 4,
        ev_store::Error::NeedsRecovery => 5,
        ev_store::Error::Conflict => 6,
        ev_store::Error::Phase => 7,
        _ => 8,
    };
    rt::exit((stage << 32) | reason)
}
#[inline(never)]
fn control(endpoint: &mut Endpoint, window: &Window, deadline: u64) -> Control {
    let request = BlockRequest::Read { sector: 2 };
    let reply = endpoint
        .call(request.encode(), deadline)
        .unwrap_or_else(|_| rt::exit(350));
    require(Response::decode(&reply) == Ok(request.success()), 351);
    let mut bytes = [0; 512];
    window.load(&mut bytes);
    Control::decode(&bytes).unwrap_or_else(|_| rt::exit(352))
}
#[inline(never)]
fn format(device: Device, deadline: u64) -> Store<Device> {
    Store::format_new(
        device,
        pending_a(),
        OWNER_A,
        BootPolicy::new(3).unwrap(),
        deadline,
    )
    .unwrap_or_else(|failure| failed(353, failure.error))
}
#[inline(never)]
fn open(device: Device, deadline: u64) -> Store<Device> {
    Store::open(device, deadline).unwrap_or_else(|failure| failed(354, failure.error))
}
#[inline(never)]
fn payload(store: &mut Store<Device>, deadline: u64) -> bool {
    let mut bytes = [0; ev_store::PAYLOAD_BYTES];
    let length = store
        .read_mutable(ObjectId::user_data(), &mut bytes, deadline)
        .unwrap_or_else(|e| failed(355, e));
    require(
        length == OWNER_A.len() && (bytes[..length] == *OWNER_A || bytes[..length] == *OWNER_B),
        356,
    );
    bytes[..length] == *OWNER_B
}
#[inline(never)]
fn operation(store: &mut Store<Device>, deadline: u64) -> ev_store::Receipt {
    store
        .execute(
            OperationId::new(1).unwrap(),
            ev_store::Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: OWNER_B,
            },
            deadline,
        )
        .unwrap_or_else(|e| failed(357, e))
}
#[inline(never)]
fn assert_pending(store: &mut Store<Device>, deadline: u64) {
    require(store.known_good().is_none(), 358);
    let selected = store
        .selected_manifest(deadline)
        .unwrap_or_else(|e| failed(359, e));
    require(selected == pending_a(), 360);
    require(
        matches!(store.boot_plan(deadline), Err(ev_store::Error::Phase)),
        361,
    );
}
#[inline(never)]
pub(super) fn run(bytes: &[u8], record: u64, stop: u64) -> ! {
    let caps = ev_block_service::client_startup(bytes).unwrap_or_else(|_| rt::exit(362));
    let window = Window::new(record);
    window.guards();
    let deadline = stop.checked_add(512).unwrap_or_else(|| rt::exit(363));
    let clock = rt::monotonic();
    require(clock.status == 0 && clock.value < stop, 364);
    let mut endpoint = Endpoint(SyncEndpoint {
        endpoint: caps.request,
    });
    let control = control(&mut endpoint, &window, deadline);
    let observer = CrashAt {
        mutation: if control.mode == Mode::Cut {
            control.cut
        } else {
            0
        },
    };
    let device = StoreRegion::with_observer(endpoint, window, stop, observer)
        .unwrap_or_else(|| rt::exit(365));
    let mut store = if control.mode == Mode::Init {
        format(device, deadline)
    } else {
        open(device, deadline)
    };
    assert_pending(&mut store, deadline);
    let was_b = payload(&mut store, deadline);
    if control.mode == Mode::Init {
        require(
            !was_b
                && store
                    .next_operation()
                    .unwrap_or_else(|e| failed(366, e))
                    .get()
                    == 1,
            367,
        );
    } else {
        match control.mode {
            Mode::Cut | Mode::Commit => require(
                !was_b
                    && store
                        .next_operation()
                        .unwrap_or_else(|e| failed(368, e))
                        .get()
                        == 1,
                369,
            ),
            Mode::Verify => require(was_b, 370),
            Mode::Recover => (),
            Mode::Init => rt::exit(371),
        }
        let receipt = operation(&mut store, deadline);
        require(receipt.operation.get() == 1 && receipt.sequence == 2, 372);
        match control.mode {
            Mode::Cut => rt::exit(373), // Every selected1..6 must have #UD already.
            Mode::Commit => require(!receipt.replayed, 374),
            Mode::Verify => require(receipt.replayed, 375),
            _ => (),
        }
        require(payload(&mut store, deadline), 376);
        let replay = operation(&mut store, deadline);
        require(
            replay.replayed && replay.operation.get() == 1 && replay.sequence == 2,
            377,
        );
        require(
            store
                .next_operation()
                .unwrap_or_else(|e| failed(378, e))
                .get()
                == 2,
            379,
        );
        assert_pending(&mut store, deadline);
    }
    let device = store.into_device();
    let mutations = device.mutations();
    let (_, window) = device.into_parts();
    let report = Completion::new(control.mode, mutations).unwrap_or_else(|| rt::exit(380));
    window.guards();
    window.publish(&report.encode());
    window.guards();
    // A real successful exit follows typed store validation. The controller
    // separately compares all physical mutation counts and cold raw snapshots.
    rt::exit(0)
}
