//! Actual profile5 ATA owner: three distinct authorized endpoint/window pairs.
//! The Root/Kernel loader must supply exact live grants and retained mappings;
//! startup parsing and numbers do not manufacture that physical ownership.
use super::{Mediated, fail, require, rpc_actor::Window};
use ev_block_service::{
    ata::{AtaPio, SessionDisk, SessionOutcome},
    workspace::{self, Client, Routes},
};
use ev_userspace_contract::{block::Response, syscall};
use ev_userspace_runtime as rt;

fn clock() -> u64 {
    let r = rt::monotonic();
    require(r.status == 0 && r.capability == 0, 380);
    r.value
}
fn pause() {
    let r = rt::yield_now();
    require(r.status == 0 && r.value == 0 && r.capability == 0, 381);
}
fn quarantine() -> ! {
    // Keep the accepted nonce and all windows quarantined until actual owner
    // retirement. Reset/idle failure is not an ACK or reusable-buffer signal.
    loop {
        pause();
    }
}
/// Actual selected guest denial probes, never a host/hardware pass by source
/// inspection. All cases must fail before any port effect; no live data command
/// is issued. Successful Block READY implies this new-feature-only check ran.
#[cfg(feature = "pio-words256")]
fn sector_preflight_denials(port_cap: u64, record: u64) {
    let base = record
        .checked_sub(509 * 4096)
        .unwrap_or_else(|| rt::exit(377));
    let cut = clock()
        .checked_add(syscall::PORT_WORDS256_MAX_TICKS)
        .unwrap_or_else(|| rt::exit(377));
    let denied = |r: rt::CapReply| {
        require(
            r.status == 1 && r.value == 0 && r.capability == 0 && r.serial == 0,
            378,
        );
    };
    for address in [
        0,
        u64::MAX - 255,
        record,
        base + 4096,
        base + 508 * 4096,
        base + 506 * 4096,
        base + 255 * 4096,
        base + 260 * 4096 - 255,
        base + (1 << 39),
    ] {
        denied(rt::call4(
            syscall::PORT_INPUT_WORDS256,
            port_cap,
            0x1e8,
            cut,
            address,
        ));
    }
    let mut bytes = [0; 512];
    let address = bytes.as_mut_ptr() as u64;
    denied(rt::call4(
        syscall::PORT_INPUT_WORDS256,
        port_cap,
        0x3ee,
        cut,
        address,
    ));
    denied(rt::call4(
        syscall::PORT_INPUT_WORDS256,
        port_cap,
        0x1e8,
        1,
        address,
    ));
    denied(rt::call4(
        syscall::PORT_OUTPUT_WORDS256,
        0,
        0x1e8,
        cut,
        address,
    ));
}
pub fn run(bytes: &[u8], record: u64, stop: u64) -> ! {
    require(rt::execution::validate(stop, clock(), true).is_ok(), 382);
    let caps = workspace::startup(bytes).unwrap_or_else(|_| rt::exit(383));
    let system = Window::at(record, 1);
    let files = Window::at(record, 2);
    let workspace = Window::at(record, 3);
    system.guards();
    files.guards();
    workspace.guards();
    let routes = Routes::new(
        caps.system_request,
        caps.file_request,
        caps.workspace_request,
    )
    .unwrap_or_else(|| rt::exit(384));
    #[cfg(feature = "pio-words256")]
    {
        // Fail before reset/IDENTIFY or any device I/O on an older Kernel.
        let info = rt::call4(syscall::PORT_WORDS256_INFO, 0, 0, 0, 0);
        require(
            info.status == 0
                && info.value == syscall::PORT_WORDS256_V1
                && info.capability == 0
                && info.serial == 0,
            379,
        );
        sector_preflight_denials(caps.ports, record);
    }
    let info = rt::call4(syscall::PORT_BATCH_INFO, 0, 0, 0, 0);
    require(
        info.status == 0
            && info.value == syscall::PORT_BATCH_V1
            && info.capability == 0
            && info.serial == 0,
        385,
    );
    let mut disk = AtaPio::new_workspace(Mediated { cap: caps.ports });
    let initial = clock()
        .checked_add(512)
        .unwrap_or_else(|| rt::exit(386))
        .min(if stop == 0 { u64::MAX - 1 } else { stop });
    disk.reset(initial).unwrap_or_else(|e| fail(387, e));
    disk.identify(initial).unwrap_or_else(|e| fail(388, e));
    let mut disk = SessionDisk::new(disk).unwrap_or_else(|_| rt::exit(389));
    let receivers = [
        caps.system_request,
        caps.file_request,
        caps.workspace_request,
    ];
    for route in receivers {
        let r = rt::call(syscall::BIND_RECEIVER, route, 0, 0);
        require(r.status == 0 && r.value == 0 && r.capability == 0, 390);
    }
    let ready_stop = if stop == 0 {
        clock().checked_add(512).unwrap_or_else(|| rt::exit(391))
    } else {
        stop
    };
    loop {
        require(clock() < ready_stop, 391);
        let r = rt::send(caps.events, workspace::READY);
        if r.status == 0 {
            require(r.value == 0 && r.capability == 0, 392);
            break;
        }
        require(r.status == 2 && r.value == 0 && r.capability == 0, 393);
        pause();
    }
    loop {
        require(rt::execution::live(stop, clock()), 394);
        let mut handled = false;
        for route in receivers {
            let Some(received) = rt::discipline::receive(route).unwrap_or_else(|_| rt::exit(395))
            else {
                continue;
            };
            handled = true;
            // Unknown clients, syntax and slice bounds fail before any window
            // access or device command. The actual receiver chooses the client.
            let response = match routes.resolve(route, received.bytes) {
                Err(_) => Response::Error { code: 1 },
                Ok(operation) => {
                    let deadline = rt::rpc_deadline();
                    require(deadline.status == 0 && deadline.capability == 0, 396);
                    if !rt::execution::accepts_deadline(stop, clock(), deadline.value, 1024) {
                        rt::discipline::reply(
                            route,
                            Response::Error { code: 1 }.encode(),
                            received.nonce,
                        )
                        .unwrap_or_else(|_| rt::exit(397));
                        continue;
                    }
                    let window = match operation.client {
                        Client::System => &system,
                        Client::Files => &files,
                        Client::Workspace => &workspace,
                    };
                    let response = match disk.command(operation.physical, window, deadline.value) {
                        SessionOutcome::Complete(response) => {
                            operation.complete(response).unwrap_or_else(|| quarantine())
                        }
                        SessionOutcome::Refused(_) => Response::Error { code: 3 },
                        SessionOutcome::Recovered(_) => Response::Error { code: 2 },
                        SessionOutcome::Quarantined(_) => quarantine(),
                    };
                    system.guards();
                    files.guards();
                    workspace.guards();
                    response
                }
            };
            rt::discipline::reply(route, response.encode(), received.nonce)
                .unwrap_or_else(|_| rt::exit(397));
        }
        if !handled {
            pause();
        }
    }
}
