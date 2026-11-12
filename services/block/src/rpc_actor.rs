//! Measured internal block transport fixture. Fixed prebound memory is accessed
//! only with volatile scalar loads/stores; no Rust reference survives a syscall.
//! The kernel enforces a single blocked client and deadlines beyond its finite
//! controller stop. This fixture does not admit timeout-driven buffer reuse.
use super::{Mediated, fail, require};
use ev_block_service::{
    ClientCapabilities, DISK_SECTORS, DriverCapabilities, PORT_BASE, RECORD, SEED, ata::AtaPio,
};
use ev_userspace_contract::{
    block::{Request, Response},
    syscall,
};
use ev_userspace_runtime as rt;

const SNAPSHOT_YIELD: u64 = 0x424c_5350;
const CALL_CANARY: u64 = 0xa923_14fd_703c_b865;

/// Page508 is mapped by the trusted inactive loader; bootstrap is page 509.
/// Startup parsing does not itself establish that mapping or its authority.
pub(super) struct Window {
    address: usize,
}
impl Window {
    pub(super) fn new(record: u64) -> Self {
        Self::at(record, 1)
    }
    pub(super) fn at(record: u64, pages: u64) -> Self {
        require(matches!(pages, 1 | 2), 300);
        Self {
            address: usize::try_from(
                record
                    .checked_sub(pages * 4096)
                    .unwrap_or_else(|| rt::exit(300)),
            )
            .unwrap_or_else(|_| rt::exit(301)),
        }
    }
    pub(super) fn snapshot(&self) -> [u8; 512] {
        core::array::from_fn(|i| {
            // SAFETY: retained prebound RW/NX page 508, exact 512-byte extent.
            unsafe { (self.address as *const u8).add(i).read_volatile() }
        })
    }
    pub(super) fn publish(&self, sector: &[u8; 512]) {
        for (i, byte) in sector.iter().copied().enumerate() {
            // SAFETY: same retained mapped frame; transport excludes concurrent
            // client execution until a real reply. No Rust alias is retained.
            unsafe { (self.address as *mut u8).add(i).write_volatile(byte) };
        }
    }
    fn matches(&self, sector: &[u8; 512]) -> bool {
        sector.iter().copied().enumerate().all(|(i, expected)| {
            // SAFETY: initialized 512-byte window, retained mapping, no borrow.
            unsafe { (self.address as *const u8).add(i).read_volatile() == expected }
        })
    }
    pub(super) fn guards(&self) {
        for i in 512..4096 {
            // SAFETY: never crosses the retained 4096-byte mapping.
            require(
                unsafe { (self.address as *const u8).add(i).read_volatile() } == 0,
                302,
            );
        }
    }
}
#[cfg(feature = "test-store-client")]
impl ev_block_service::store_io::Window for Window {
    fn load(&self, out: &mut ev_store::Sector) {
        for (i, byte) in out.iter_mut().enumerate() {
            // SAFETY: exact initialized fixed page extent; real single-client
            // stop-bound transport excludes concurrent server use on return.
            *byte = unsafe { (self.address as *const u8).add(i).read_volatile() };
        }
    }
    fn store(&self, bytes: &ev_store::Sector) {
        self.publish(bytes);
    }
}
fn clock() -> u64 {
    let reply = rt::monotonic();
    require(reply.status == 0 && reply.capability == 0, 303);
    reply.value
}
fn yield_now() {
    let reply = rt::yield_now();
    require(
        reply.status == 0 && reply.value == 0 && reply.capability == 0,
        304,
    );
}

pub(super) fn driver(caps: DriverCapabilities, record: u64) -> ! {
    let window = Window::new(record);
    window.guards();
    let mut disk = AtaPio::new(Mediated { cap: caps.ports });
    let startup_deadline = clock().checked_add(512).unwrap_or_else(|| rt::exit(305));
    disk.reset(startup_deadline)
        .unwrap_or_else(|f| fail(310, f));
    disk.identify(startup_deadline)
        .unwrap_or_else(|f| fail(311, f));
    loop {
        let received = rt::call4(syscall::RECEIVE_RPC, caps.request, 0, 0, 0);
        if received.status == 2 {
            require(
                received.value == 0 && received.capability == 0 && received.serial == 0,
                306,
            );
            yield_now();
            continue;
        }
        require(
            received.status == 0 && received.capability == 0 && received.serial != 0,
            307,
        );
        let request =
            Request::decode(&received.value.to_le_bytes()).unwrap_or_else(|_| rt::exit(308));
        // Complete syntax and geometry checks precede buffer access or device
        // effects. No sector authority is granted by the scalar header itself.
        require(request.in_bounds(DISK_SECTORS), 309);
        let deadline = rt::rpc_deadline();
        require(
            deadline.status == 0 && deadline.capability == 0 && deadline.value > clock(),
            312,
        );
        match request {
            Request::Read { sector } => {
                let mut bytes = [0; 512];
                disk.read_sector(sector, &mut bytes, deadline.value)
                    .unwrap_or_else(|f| fail(313, f));
                window.publish(&bytes);
            }
            Request::Write { sector } => {
                let bytes = window.snapshot();
                // Real adversarial fixture hook: controller mutates the shared
                // source after this private copy, before the ATA command.
                let yielded = rt::call(syscall::YIELD, SNAPSHOT_YIELD, 0, 0);
                require(
                    yielded.status == 0 && yielded.value == 0 && yielded.capability == 0,
                    314,
                );
                disk.write_sector(sector, &bytes, deadline.value)
                    .unwrap_or_else(|f| fail(315, f));
            }
            Request::Flush => disk.flush(deadline.value).unwrap_or_else(|f| fail(316, f)),
        }
        disk.idle(deadline.value).unwrap_or_else(|f| fail(317, f));
        window.guards();
        let reply = rt::call4(
            syscall::REPLY_RPC,
            caps.request,
            u64::from_le_bytes(request.success().encode()),
            0,
            received.serial,
        );
        require(
            reply.status == 0 && reply.value == 0 && reply.capability == 0 && reply.serial == 0,
            318,
        );
    }
}

fn raw_call(endpoint: u64, bytes: [u8; 8], deadline: u64, status: u64) -> rt::CapReply {
    let reply = rt::call4(
        syscall::RPC_CALL,
        endpoint,
        u64::from_le_bytes(bytes),
        deadline,
        CALL_CANARY,
    );
    require(
        reply.status == status && reply.capability == 0 && reply.serial == CALL_CANARY,
        320,
    );
    if status != 0 {
        require(reply.value == 0, 321);
    }
    reply
}
fn call(endpoint: u64, request: Request, deadline: u64) {
    let reply = raw_call(endpoint, request.encode(), deadline, 0);
    require(
        Response::decode(&reply.value.to_le_bytes()) == Ok(request.success()),
        322,
    );
}
pub(super) fn client(caps: ClientCapabilities, record: u64, stop: u64, write: bool) -> ! {
    let window = Window::new(record);
    let deadline = stop.checked_add(512).unwrap_or_else(|| rt::exit(323));
    require(stop > clock(), 324);
    window.guards();
    let read_seed = Request::Read { sector: 0 };
    raw_call(caps.request, read_seed.encode(), stop, 4);
    let mut version = read_seed.encode();
    version[2] = 2;
    raw_call(caps.request, version, deadline, 3);
    let mut reserved = Request::Flush.encode();
    reserved[4] = 1;
    raw_call(caps.request, reserved, deadline, 3);
    let denied = rt::call4(syscall::PORT_INPUT, caps.buffer, u64::from(PORT_BASE), 2, 0);
    require(
        denied.status == 1 && denied.value == 0 && denied.capability == 0 && denied.serial == 0,
        325,
    );
    call(caps.request, read_seed, deadline);
    require(window.matches(&SEED), 326);
    window.guards();
    if write {
        window.publish(&RECORD);
        call(caps.request, Request::Write { sector: 1 }, deadline);
        // Shared source was deliberately poisoned while this thread really
        // waited; Read1, not this stale source window, proves disk contents.
        call(caps.request, Request::Flush, deadline);
    }
    call(caps.request, Request::Read { sector: 1 }, deadline);
    require(window.matches(&RECORD), 327);
    window.guards();
    rt::exit(0)
}
