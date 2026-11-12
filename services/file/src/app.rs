use crate::{now, require, window::Window, yield_now};
use ev_file::{ErrorCode, Payload, Request, Response};
use ev_userspace_contract::{
    file_test::{CALL, Completion, DATA_A, DATA_B, EARLY, Mode, READY, REPLY},
    syscall,
};
use ev_userspace_runtime as rt;
use sha2::{Digest as _, Sha256};

struct Client {
    window: Window,
    deadline: u64,
    requests: u64,
}
impl Client {
    fn call(&mut self, endpoint: u64, frame: [u8; 256]) -> Response {
        self.window.guards(256);
        self.window.publish(&frame);
        let reply = rt::call(
            syscall::RPC_CALL,
            endpoint,
            u64::from_le_bytes(CALL),
            self.deadline,
        );
        require(
            reply.status == 0 && reply.capability == 0 && reply.value.to_le_bytes() == REPLY,
            640,
        );
        self.requests = self
            .requests
            .checked_add(1)
            .unwrap_or_else(|| rt::exit(641));
        self.window.guards(256);
        Response::decode(&self.window.load()).unwrap_or_else(|_| rt::exit(642))
    }
    fn read(&mut self, endpoint: u64) -> (u64, Payload) {
        match self.call(endpoint, Request::Read.encode()) {
            Response::Read { counter, payload } => (counter, payload),
            _ => rt::exit(643),
        }
    }
    fn error(&mut self, endpoint: u64, frame: [u8; 256], code: ErrorCode) {
        require(self.call(endpoint, frame) == Response::Error { code }, 644);
    }
}
fn replace(counter: u64, bytes: &[u8]) -> [u8; 256] {
    Request::Replace {
        counter,
        payload: Payload::new(bytes).unwrap_or_else(|_| rt::exit(645)),
    }
    .encode()
}
pub fn run(bytes: &[u8], record: u64, stop: u64) -> ! {
    let caps = ev_file_service::app_startup(bytes).unwrap_or_else(|_| rt::exit(646));
    let window = Window::at(record, 2);
    window.guards(256);
    let deadline = stop.checked_add(512).unwrap_or_else(|| rt::exit(648));
    let canary = 0x4649_4c45_4541_524c;
    let early = rt::call4(
        syscall::RPC_CALL,
        caps.read_only,
        u64::from_le_bytes(CALL),
        deadline,
        canary,
    );
    require(
        early.status == 1 && early.value == 0 && early.capability == 0 && early.serial == canary,
        656,
    );
    window.marker(EARLY);
    while window.load()[..8] != READY {
        require(now() < stop, 647);
        yield_now();
    }
    let port = rt::call4(syscall::PORT_INPUT, caps.app, 0x1e8, 1, 0);
    require(
        port.status != 0 && port.capability == 0 && port.serial == 0,
        649,
    );
    let backend = rt::call(
        syscall::RPC_CALL,
        caps.app,
        u64::from_le_bytes(CALL),
        deadline,
    );
    require(backend.status != 0 && backend.capability == 0, 650);
    let mut client = Client {
        window,
        deadline,
        requests: 0,
    };
    let (counter, payload) = client.read(caps.read_only);
    let mode = if counter == 0 && payload.as_slice() == DATA_A {
        Mode::Write
    } else if counter == 1 && payload.as_slice() == DATA_B {
        Mode::Verify
    } else {
        rt::exit(651)
    };
    let mut result = Completion {
        mode,
        object: 1,
        counter: 0,
        requests: 0,
        ro_denied: 0,
        malformed: 0,
        invalid_counter: 0,
        skipped: 0,
        conflicting: 0,
        duplicates: 0,
        port_denied: 1,
        block_denied: 1,
        private_snapshot: 0,
        payload: [0; 32],
    };
    client.error(caps.read_only, replace(1, DATA_B), ErrorCode::Denied);
    result.ro_denied += 1;
    let mut malformed = Request::Read.encode();
    malformed[10] = 99;
    client.error(caps.read_write, malformed, ErrorCode::Malformed);
    result.malformed += 1;
    let mut malformed = Request::Read.encode();
    malformed[24] = 1; // No client object selector exists.
    client.error(caps.read_only, malformed, ErrorCode::Malformed);
    result.malformed += 1;
    for counter in [0, u64::MAX] {
        client.error(
            caps.read_write,
            replace(counter, DATA_B),
            ErrorCode::InvalidCounter,
        );
        result.invalid_counter += 1;
    }
    if mode == Mode::Write {
        client.error(caps.read_write, replace(2, DATA_B), ErrorCode::Skipped);
        result.skipped += 1;
        require(
            client.call(caps.read_write, replace(1, DATA_B))
                == Response::Replaced {
                    counter: 1,
                    replayed: false,
                },
            652,
        );
        result.private_snapshot = 1;
        require(
            client.call(caps.read_write, replace(1, DATA_B))
                == Response::Replaced {
                    counter: 1,
                    replayed: true,
                },
            653,
        );
        result.duplicates += 1;
        client.error(
            caps.read_write,
            replace(1, b"conflicting-file-content"),
            ErrorCode::Conflict,
        );
        result.conflicting += 1;
    }
    let (counter, payload) = client.read(caps.read_only);
    require(counter == 1 && payload.as_slice() == DATA_B, 654);
    result.counter = counter;
    result.requests = client.requests;
    result.payload = Sha256::digest(payload.as_slice()).into();
    let encoded = result.encode();
    require(Completion::decode(&encoded) == Ok(result), 655);
    client.window.guards(256);
    client.window.publish(&encoded);
    client.window.guards(256);
    rt::exit(0)
}
