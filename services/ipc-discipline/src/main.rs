#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_ipc_discipline::{Capabilities, Pair};
use ev_userspace_contract::{SIZE, echo};
use ev_userspace_runtime::{
    self as runtime,
    discipline::{self, Received},
};
// SAFETY: shared entry preserves RDI/RSI startup data and fixture-bound RDX/RCX
// local-role/process-index while aligning the kernel-supplied private SysV stack.
global_asm!(ev_userspace_runtime::start_assembly!());
const VALUE: u32 = 0x01020304;
const DEPTH: bool = cfg!(feature = "depth");
fn require(ok: bool, code: u64) {
    if !ok {
        runtime::exit(code);
    }
}
fn yield_now() {
    require(runtime::yield_now().status == 0, 400);
}
fn now() -> u64 {
    let reply = runtime::monotonic();
    require(reply.status == 0, 401);
    reply.value
}
fn future() -> u64 {
    now().checked_add(256).unwrap_or_else(|| runtime::exit(402))
}
fn inherited() -> u64 {
    let reply = runtime::rpc_deadline();
    require(reply.status == 0 && reply.value > now(), 403);
    reply.value
}
fn receive(pair: Pair) -> Received {
    loop {
        match discipline::receive(pair.incoming) {
            Ok(Some(received)) => {
                require(
                    echo::Request::decode(&received.bytes) == Ok(echo::Request { value: VALUE }),
                    404,
                );
                return received;
            }
            Ok(None) => yield_now(),
            Err(_) => runtime::exit(405),
        }
    }
}
fn call(
    pair: Pair,
    deadline: u64,
) -> Result<echo::Response, echo::ClientError<runtime::SyncError>> {
    echo::client_call(
        &mut runtime::SyncEndpoint {
            endpoint: pair.outgoing,
        },
        VALUE,
        deadline,
    )
}
fn success(pair: Pair, deadline: u64) {
    require(
        call(pair, deadline) == Ok(echo::Response { value: VALUE }),
        406,
    );
}
fn rejection(pair: Pair, deadline: u64, status: u64) {
    require(
        call(pair, deadline)
            == Err(echo::ClientError::Transport(runtime::SyncError::Status(
                status,
            ))),
        407,
    );
}
fn respond(pair: Pair, received: Received) {
    let bytes = echo::server_dispatch(&received.bytes, 0, |request| echo::Response {
        value: request.value,
    })
    .unwrap_or_else(|_| runtime::exit(408));
    require(
        discipline::reply(pair.incoming, bytes, received.nonce).is_ok(),
        409,
    );
}
fn park() -> ! {
    loop {
        yield_now();
    }
}
fn chain(caps: Capabilities, process_index: u64, local_role: u64) -> ! {
    require(local_role == 0, 410);
    let pair = caps.pairs[0];
    match process_index {
        0 => {
            let acquired =
                discipline::mutex_acquire(caps.mutex.unwrap_or_else(|| runtime::exit(411)))
                    .unwrap_or_else(|_| runtime::exit(412));
            require(!acquired.abandoned, 413);
            // This is the actual generated client while its real, kernel-bound
            // NO_IPC_WAIT mutex lease remains held; rejection precedes waiting.
            rejection(pair, future(), 7);
            require(acquired.guard.release().is_ok(), 414);
            success(pair, future());
            runtime::exit(0)
        }
        1 => {
            let received = receive(pair);
            let deadline = inherited();
            // Descendants cannot extend the actual protected parent deadline.
            rejection(
                pair,
                deadline
                    .checked_add(1)
                    .unwrap_or_else(|| runtime::exit(415)),
                10,
            );
            success(pair, deadline);
            respond(pair, received);
            park()
        }
        2 => {
            let received = receive(pair);
            let deadline = inherited();
            // The outgoing role is the declared A receiver; A is an active
            // ancestor already blocked on this exact forward chain.
            rejection(pair, deadline, 8);
            respond(pair, received);
            park()
        }
        _ => runtime::exit(416),
    }
}
fn depth(caps: Capabilities, process_index: u64, local_role: u64) -> ! {
    let rank =
        ev_ipc_discipline::rank(process_index, local_role).unwrap_or_else(|| runtime::exit(417));
    if local_role == 0 {
        require(discipline::spawn(1).is_ok(), 418);
        require(discipline::spawn(2).is_ok(), 419);
    }
    let pair = caps.pairs[local_role as usize];
    if rank == 0 {
        // This RX|CONTROL handle aliases rank3 in our own domain. Possessing it
        // cannot make rank0 the actual registered servicing thread for rank3.
        require(
            matches!(
                discipline::receive(pair.incoming),
                Err(discipline::Error::Status(1))
            ),
            423,
        );
        success(pair, future());
        runtime::exit(0);
    }
    let received = receive(pair);
    let deadline = inherited();
    if rank == 8 {
        // This existing rank1 route would also reach an ancestor. The mandatory
        // depth check rejects attempt9 first without a ninth endpoint object.
        rejection(pair, deadline, 9);
    } else {
        success(pair, deadline);
    }
    respond(pair, received);
    // Exit remains process-wide: a secondary role must not terminate its
    // ancestors in the same process. The owner stops all after rank0 Exit0.
    park()
}

// SAFETY: unique measured entry; the trusted fixture sets truthful retained
// startup RDI/RSI plus assigned local-role RDX/process-index RCX for this actual
// thread. These extra arguments are routing metadata, never identity authority.
#[unsafe(no_mangle)]
extern "C" fn ev_user_main(record: u64, length: u64, local_role: u64, process_index: u64) -> ! {
    require(
        length == SIZE as u64
            && record != 0
            && record.is_multiple_of(4096)
            && record <= (1 << 47) - 4096,
        420,
    );
    require(
        ev_ipc_discipline::rank(process_index, local_role).is_some(),
        421,
    );
    // SAFETY: exact bounded slice lies within the initialized readonly retained
    // bootstrap page validated by actual executable/process admission.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, SIZE) };
    let caps = ev_ipc_discipline::startup(bytes, DEPTH).unwrap_or_else(|_| runtime::exit(422));
    if DEPTH {
        depth(caps, process_index, local_role)
    } else {
        chain(caps, process_index, local_role)
    }
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    runtime::exit(499)
}
