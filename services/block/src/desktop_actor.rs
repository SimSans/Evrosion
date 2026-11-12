//! Actual single-thread ATA owner for two separately mapped/authorized clients.
use super::{Mediated, fail, require, rpc_actor::Window};
use ev_block_service::{
    ata::AtaPio,
    desktop::{self, Routes},
};
use ev_store::desktop::Client;
use ev_userspace_contract::{
    block::{Request, Response},
    syscall,
};
use ev_userspace_runtime as rt;
fn clock() -> u64 {
    let r = rt::monotonic();
    require(r.status == 0 && r.capability == 0, 350);
    r.value
}
fn yield_now() {
    let r = rt::yield_now();
    require(r.status == 0 && r.value == 0 && r.capability == 0, 351);
}
pub fn run(bytes: &[u8], record: u64, stop: u64) -> ! {
    let caps = desktop::startup(bytes).unwrap_or_else(|_| rt::exit(352));
    let system = Window::at(record, 1);
    let files = Window::at(record, 2);
    system.guards();
    files.guards();
    let routes = if cfg!(feature = "native-driver") {
        Routes::new_native(caps.system_request, caps.file_request)
    } else {
        Routes::new(caps.system_request, caps.file_request)
    }
    .unwrap_or_else(|| rt::exit(353));
    let mut disk = AtaPio::new(Mediated { cap: caps.ports });
    let initial = clock()
        .checked_add(512)
        .unwrap_or_else(|| rt::exit(354))
        .min(stop);
    disk.reset(initial).unwrap_or_else(|e| fail(355, e));
    disk.identify(initial).unwrap_or_else(|e| fail(356, e));
    for route in [caps.system_request, caps.file_request] {
        let r = rt::call(syscall::BIND_RECEIVER, route, 0, 0);
        require(r.status == 0 && r.value == 0 && r.capability == 0, 357);
    }
    loop {
        require(clock() < stop, 358);
        let r = rt::send(caps.events, desktop::READY);
        if r.status == 0 {
            require(r.value == 0 && r.capability == 0, 359);
            break;
        }
        require(r.status == 2 && r.value == 0 && r.capability == 0, 360);
        yield_now();
    }
    loop {
        require(clock() < stop, 361);
        let mut handled = false;
        for route in [caps.system_request, caps.file_request] {
            let Some(received) = rt::discipline::receive(route).unwrap_or_else(|_| rt::exit(362))
            else {
                continue;
            };
            handled = true;
            let decoded = routes.resolve(route, received.bytes);
            let response = match decoded {
                Err(_) => Response::Error { code: 1 },
                Ok(operation) => {
                    let deadline = rt::rpc_deadline();
                    require(
                        deadline.status == 0
                            && deadline.capability == 0
                            && deadline.value > stop
                            && deadline.value
                                <= stop.checked_add(1024).unwrap_or_else(|| rt::exit(363)),
                        364,
                    );
                    let window = match operation.client {
                        Client::System => &system,
                        Client::Files => &files,
                    };
                    match operation.physical {
                        Request::Read { sector } => {
                            let mut sector_bytes = [0; 512];
                            disk.read_sector(sector, &mut sector_bytes, deadline.value)
                                .unwrap_or_else(|e| fail(365, e));
                            window.publish(&sector_bytes);
                        }
                        Request::Write { sector } => {
                            let private = window.snapshot();
                            disk.write_sector(sector, &private, deadline.value)
                                .unwrap_or_else(|e| fail(366, e));
                        }
                        Request::Flush => {
                            disk.flush(deadline.value).unwrap_or_else(|e| fail(367, e))
                        }
                    }
                    disk.idle(deadline.value).unwrap_or_else(|e| fail(368, e));
                    system.guards();
                    files.guards();
                    operation.reply
                }
            };
            rt::discipline::reply(route, response.encode(), received.nonce)
                .unwrap_or_else(|_| rt::exit(369));
        }
        if !handled {
            yield_now();
        }
    }
}
