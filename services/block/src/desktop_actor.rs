//! Actual single-thread ATA owner for two separately mapped/authorized clients.
use super::{Mediated, fail, require, rpc_actor::Window};
use ev_block_service::{
    ata::AtaPio,
    desktop::{self, Routes},
};
use ev_store::desktop::Client;
#[cfg(not(feature = "native-session"))]
use ev_userspace_contract::block::Request;
use ev_userspace_contract::{block::Response, syscall};
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
#[cfg(feature = "native-session")]
impl ev_block_service::ata::SessionWindow for Window {
    fn snapshot(&self) -> [u8; 512] {
        Window::snapshot(self)
    }
    fn publish(&self, bytes: &[u8; 512]) {
        Window::publish(self, bytes);
    }
}
#[cfg(feature = "native-session")]
fn quarantine() -> ! {
    // The received nonce is deliberately retained. No request/response memory
    // or further PIO is touched; the kernel's finite quiescence owner decides
    // actual fencing/retirement. Yielding is not a reusable-buffer ACK.
    loop {
        yield_now();
    }
}
pub fn run(bytes: &[u8], record: u64, stop: u64) -> ! {
    require(
        rt::execution::validate(stop, clock(), cfg!(feature = "native-session")).is_ok(),
        352,
    );
    let caps = desktop::startup(bytes).unwrap_or_else(|_| rt::exit(352));
    let system = Window::at(record, 1);
    let files = Window::at(record, 2);
    system.guards();
    files.guards();
    #[cfg(feature = "native-network")]
    let routes = Routes::new_network(caps.system_request, caps.file_request);
    #[cfg(not(feature = "native-network"))]
    let routes = if cfg!(feature = "native-session") {
        Routes::new_session(caps.system_request, caps.file_request)
    } else if cfg!(feature = "native-driver") {
        Routes::new_native(caps.system_request, caps.file_request)
    } else {
        Routes::new(caps.system_request, caps.file_request)
    };
    let routes = routes.unwrap_or_else(|| rt::exit(353));
    #[cfg(feature = "pio-word4")]
    {
        // Mandatory before reset/identify/any port instruction. An old Kernel
        // rejects INFO with no I/O; there is no silent scalar fallback or new
        // meaning assigned to the original Native bootstrap ABI.
        let info = rt::call4(syscall::PORT_BATCH_INFO, 0, 0, 0, 0);
        require(
            info.status == 0
                && info.value == syscall::PORT_BATCH_V1
                && info.capability == 0
                && info.serial == 0,
            370,
        );
    }
    let mut disk = AtaPio::new(Mediated { cap: caps.ports });
    let initial = clock()
        .checked_add(512)
        .unwrap_or_else(|| rt::exit(354))
        .min(if stop == 0 { u64::MAX - 1 } else { stop });
    disk.reset(initial).unwrap_or_else(|e| fail(355, e));
    disk.identify(initial).unwrap_or_else(|e| fail(356, e));
    #[cfg(feature = "native-session")]
    let mut disk = ev_block_service::ata::SessionDisk::new(disk).unwrap_or_else(|_| rt::exit(356));
    for route in [caps.system_request, caps.file_request] {
        let r = rt::call(syscall::BIND_RECEIVER, route, 0, 0);
        require(r.status == 0 && r.value == 0 && r.capability == 0, 357);
    }
    let ready_stop = if stop == 0 {
        clock().checked_add(512).unwrap_or_else(|| rt::exit(358))
    } else {
        stop
    };
    loop {
        require(clock() < ready_stop, 358);
        let r = rt::send(caps.events, desktop::READY);
        if r.status == 0 {
            require(r.value == 0 && r.capability == 0, 359);
            break;
        }
        require(r.status == 2 && r.value == 0 && r.capability == 0, 360);
        yield_now();
    }
    loop {
        require(rt::execution::live(stop, clock()), 361);
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
                    if stop == 0
                        && !rt::execution::accepts_deadline(0, clock(), deadline.value, 1024)
                    {
                        // A genuine late delivery still returns its protected
                        // nonce: no PIO or shared-window access occurred.
                        rt::discipline::reply(
                            route,
                            Response::Error { code: 1 }.encode(),
                            received.nonce,
                        )
                        .unwrap_or_else(|_| rt::exit(369));
                        continue;
                    }
                    require(
                        deadline.status == 0
                            && deadline.capability == 0
                            && rt::execution::accepts_deadline(stop, clock(), deadline.value, 1024),
                        364,
                    );
                    let window = match operation.client {
                        Client::System => &system,
                        Client::Files => &files,
                    };
                    #[cfg(not(feature = "native-session"))]
                    let response = {
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
                        operation.reply
                    };
                    #[cfg(feature = "native-session")]
                    let response = match disk.command(operation.physical, window, deadline.value) {
                        ev_block_service::ata::SessionOutcome::Complete(response) => {
                            operation.complete(response).unwrap_or_else(|| quarantine())
                        }
                        ev_block_service::ata::SessionOutcome::Refused(_) => {
                            Response::Error { code: 3 }
                        }
                        // Error2 requires the durable backend to stay poisoned.
                        // Reset/idle is not write rollback or permission to retry.
                        ev_block_service::ata::SessionOutcome::Recovered(_) => {
                            Response::Error { code: 2 }
                        }
                        ev_block_service::ata::SessionOutcome::Quarantined(_) => quarantine(),
                    };
                    system.guards();
                    files.guards();
                    response
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
