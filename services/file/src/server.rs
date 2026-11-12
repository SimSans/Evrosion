use crate::{now, require, window::Window, yield_now};
use ev_block_service::store_io::{Endpoint, StoreRegion, Wire};
use ev_file::{Bindings, Envelope, Gateway, Request, Response};
use ev_store::{BootPolicy, GenerationId, GenerationManifest, Store};
use ev_userspace_contract::{
    block,
    file_test::{CALL, COPY_TAG, Control, DATA_A, EARLY, Mode, REPLY},
    syscall,
};
use ev_userspace_runtime::{self as rt, SyncEndpoint};

type Device = StoreRegion<Endpoint, Window>;
fn failure(error: ev_store::Error<ev_block_service::store_io::Error<rt::SyncError>>) -> ! {
    let code = match error {
        ev_store::Error::Corrupt => 1,
        ev_store::Error::NotBlank => 2,
        ev_store::Error::Unformatted => 3,
        ev_store::Error::Io(_) => 4,
        _ => 5,
    };
    rt::exit(610 + code)
}
#[inline(never)]
fn control(endpoint: &mut Endpoint, window: &Window, deadline: u64) -> Control {
    let request = block::Request::Read { sector: 2 };
    let reply = endpoint
        .call(request.encode(), deadline)
        .unwrap_or_else(|_| rt::exit(616));
    require(
        block::Response::decode(&reply) == Ok(request.success()),
        617,
    );
    let mut bytes = [0; 512];
    ev_block_service::store_io::Window::load(window, &mut bytes);
    Control::decode(&bytes).unwrap_or_else(|_| rt::exit(618))
}
#[inline(never)]
fn format(device: Device, deadline: u64) -> Store<Device> {
    let mut bytes = [0; 256];
    let length = Envelope::initial(DATA_A)
        .unwrap_or_else(|_| rt::exit(619))
        .encode(&mut bytes);
    // Deliberately unresolved Pending generation metadata for this File/Object
    // interface proof. Formatting does not invent admission/health/KnownGood.
    let pending = GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [0x11; 32],
        supervisor_image: [0x22; 32],
        abi: ev_userspace_contract::ABI,
        health_contract: [0x33; 32],
        health_version: 1,
        required_checks: 3,
    };
    Store::format_new(
        device,
        pending,
        &bytes[..length],
        BootPolicy::new(3).unwrap(),
        deadline,
    )
    .unwrap_or_else(|rejected| failure(rejected.error))
}
#[inline(never)]
fn open(device: Device, deadline: u64) -> Store<Device> {
    Store::open(device, deadline).unwrap_or_else(|rejected| failure(rejected.error))
}

pub fn run(bytes: &[u8], record: u64, stop: u64) -> ! {
    let caps = ev_file_service::server_startup(bytes).unwrap_or_else(|_| rt::exit(620));
    let io = Window::at(record, 1);
    let app = Window::at(record, 2);
    io.guards(512);
    app.guards(256);
    let deadline = stop.checked_add(512).unwrap_or_else(|| rt::exit(621));
    require(now() < stop, 622);
    // Deterministic pre-bind negative: the app records its real rejected call
    // before this actor can initialize or bind either File receive route.
    while app.load()[..8] != EARLY {
        require(now() < stop, 630);
        yield_now();
    }
    let mut endpoint = Endpoint(SyncEndpoint {
        endpoint: caps.block,
    });
    let control = control(&mut endpoint, &io, deadline);
    let device = StoreRegion::new(endpoint, io, stop).unwrap_or_else(|| rt::exit(623));
    let store = if control.mode == Mode::Write {
        format(device, deadline)
    } else {
        open(device, deadline)
    };
    let mut gateway = Gateway::new(
        store,
        Bindings::new(caps.read_only, caps.read_write).unwrap_or_else(|| rt::exit(624)),
    );
    for route in [caps.read_only, caps.read_write] {
        let bound = rt::call(syscall::BIND_RECEIVER, route, 0, 0);
        require(
            bound.status == 0 && bound.value == 0 && bound.capability == 0,
            631,
        );
    }
    app.ready();
    let mut copied = false;
    loop {
        let mut received_any = false;
        for route in [caps.read_only, caps.read_write] {
            let received = rt::call4(syscall::RECEIVE_RPC, route, 0, 0, 0);
            if received.status == 2 {
                require(
                    received.value == 0 && received.capability == 0 && received.serial == 0,
                    625,
                );
                continue;
            }
            require(
                received.status == 0
                    && received.capability == 0
                    && received.serial != 0
                    && received.value.to_le_bytes() == CALL,
                626,
            );
            received_any = true;
            app.guards(256);
            let private = app.load();
            if !copied
                && route == caps.read_write
                && matches!(
                    Request::decode(&private),
                    Ok(Request::Replace { counter: 1, .. })
                )
            {
                let yielded = rt::call(syscall::YIELD, COPY_TAG, 0, 0);
                require(
                    yielded.status == 0 && yielded.value == 0 && yielded.capability == 0,
                    627,
                );
                copied = true;
            }
            let inherited = rt::rpc_deadline();
            require(
                inherited.status == 0 && inherited.value == deadline && inherited.capability == 0,
                628,
            );
            let response = match gateway.handle_frame(route, &private, inherited.value) {
                Ok(response) => response,
                Err(error) => Response::Error { code: error.code() },
            };
            app.publish(&response.encode());
            app.guards(256);
            let replied = rt::call4(
                syscall::REPLY_RPC,
                route,
                u64::from_le_bytes(REPLY),
                0,
                received.serial,
            );
            require(
                replied.status == 0
                    && replied.value == 0
                    && replied.capability == 0
                    && replied.serial == 0,
                629,
            );
        }
        if !received_any {
            yield_now();
        }
    }
}
