//! Two region-isolated desktop objects. System health has no File backend cap.
use crate::{now, require, window::Window, yield_now};
use ev_block_service::store_io::{DesktopEndpoint, DesktopFiles, FileRegion};
use ev_file::{
    Envelope, Response,
    desktop::{self, DesktopBindings, DesktopGateway, MetadataQuery, Object},
};
use ev_store::{BootPolicy, GenerationId, GenerationManifest, Store};
use ev_userspace_contract::{
    file_test::{CALL, REPLY},
    syscall,
};
use ev_userspace_runtime as rt;
type Device<'a> = FileRegion<'a, DesktopEndpoint, Window>;
fn pending_container(object: Object) -> GenerationManifest {
    // Unresolved data-container metadata only, as in the existing File proof.
    // Never admitted/healthy/known-good; the actual System generation belongs
    // exclusively to the independent System region and Root health observer.
    let tag = object.stable_id() as u8;
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [tag; 32],
        supervisor_image: [0x22; 32],
        abi: ev_userspace_contract::ABI,
        health_contract: [0x33; 32],
        health_version: 1,
        required_checks: 3,
    }
}
fn open(device: Device<'_>, deadline: u64) -> Store<Device<'_>> {
    Store::open(device, deadline).unwrap_or_else(|_| rt::exit(640))
}
fn provision(device: Device<'_>, object: Object, deadline: u64) -> Store<Device<'_>> {
    let mut bytes = [0; 256];
    let seed = match object {
        Object::Notes => desktop::SEED_NOTES,
        Object::Private => desktop::SEED_PRIVATE,
    };
    let length = Envelope::initial(seed)
        .unwrap_or_else(|_| rt::exit(641))
        .encode(&mut bytes);
    Store::format_new(
        device,
        pending_container(object),
        &bytes[..length],
        BootPolicy::new(3).unwrap(),
        deadline,
    )
    .unwrap_or_else(|_| rt::exit(642))
}
fn send_ready(endpoint: u64, stop: u64) {
    loop {
        require(now() < stop, 643);
        let r = rt::send(endpoint, desktop::READY);
        if r.status == 0 {
            require(r.value == 0 && r.capability == 0, 644);
            return;
        }
        require(r.status == 2 && r.value == 0 && r.capability == 0, 645);
        yield_now();
    }
}
pub fn run(bytes: &[u8], record: u64, stop: u64) -> ! {
    let caps = ev_file_service::desktop_startup(bytes).unwrap_or_else(|_| rt::exit(646));
    let io = Window::at(record, 1);
    let app = Window::at(record, 2);
    io.guards(512);
    app.guards(256);
    let deadline = stop.checked_add(512).unwrap_or_else(|| rt::exit(647));
    require(now() < stop, 648);
    let transport = DesktopEndpoint::new(caps.block, stop).unwrap_or_else(|| rt::exit(649));
    let mut backend = DesktopFiles::new(transport, io, stop).unwrap_or_else(|| rt::exit(650));
    let (mut notes, mut private) = backend.regions();
    let (notes, private) = if cfg!(feature = "desktop-provision") {
        // Explicit NEW profile only. Preflight BOTH before the first mutation;
        // a partial I/O failure is still not a cross-volume atomic transaction.
        ev_store::desktop::require_blank(&mut notes, deadline).unwrap_or_else(|_| rt::exit(651));
        ev_store::desktop::require_blank(&mut private, deadline).unwrap_or_else(|_| rt::exit(652));
        (
            provision(notes, Object::Notes, deadline),
            provision(private, Object::Private, deadline),
        )
    } else {
        (open(notes, deadline), open(private, deadline))
    };
    let bindings = DesktopBindings::new(
        caps.notes_ro,
        caps.notes_rw,
        caps.private_ro,
        caps.private_rw,
    )
    .unwrap_or_else(|| rt::exit(653));
    let mut gateway = DesktopGateway::new(notes, private, bindings);
    for route in [
        caps.notes_ro,
        caps.notes_rw,
        caps.private_ro,
        caps.private_rw,
    ] {
        let r = rt::call(syscall::BIND_RECEIVER, route, 0, 0);
        require(r.status == 0 && r.value == 0 && r.capability == 0, 654);
    }
    app.ready();
    send_ready(caps.events, stop);
    loop {
        require(now() < stop, 655);
        let mut handled = false;
        for route in [
            caps.notes_ro,
            caps.notes_rw,
            caps.private_ro,
            caps.private_rw,
        ] {
            let Some(received) = rt::discipline::receive(route).unwrap_or_else(|_| rt::exit(656))
            else {
                continue;
            };
            handled = true;
            let inherited = rt::rpc_deadline();
            require(
                inherited.status == 0
                    && inherited.capability == 0
                    && inherited.value > stop
                    && inherited.value <= stop.checked_add(1024).unwrap_or_else(|| rt::exit(657)),
                657,
            );
            let reply = if received.bytes == CALL {
                app.guards(256);
                let private = app.load();
                let response = match gateway.handle_frame(route, &private, inherited.value) {
                    Ok(value) => value,
                    Err(error) => Response::Error { code: error.code() },
                };
                app.publish(&response.encode());
                app.guards(256);
                REPLY
            } else {
                match MetadataQuery::decode(received.bytes) {
                    Ok(query) if route == caps.notes_ro || route == caps.private_ro => {
                        // No AppFile memory load/store on this path. A valid
                        // query backend failure becomes real process failure,
                        // never an ambiguous fabricated64-bit metadata word.
                        gateway
                            .metadata_word(route, query, inherited.value)
                            .unwrap_or_else(|_| rt::exit(658))
                            .to_le_bytes()
                    }
                    Ok(_) => *b"FME1\x02\0\0\0",
                    Err(_) => *b"FME1\x01\0\0\0",
                }
            };
            rt::discipline::reply(route, reply, received.nonce).unwrap_or_else(|_| rt::exit(659));
        }
        if !handled {
            yield_now();
        }
    }
}
