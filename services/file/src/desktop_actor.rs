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
    Store::open(device, deadline).unwrap_or_else(|rejected| {
        #[cfg(feature = "native-session")]
        rt::exit(open_failure_code(&rejected.error));
        #[cfg(not(feature = "native-session"))]
        {
            let _ = rejected;
            rt::exit(640)
        }
    })
}
#[cfg(feature = "native-session")]
fn open_failure_code(
    error: &ev_store::Error<
        ev_block_service::store_io::Error<ev_block_service::store_io::DesktopTransportError>,
    >,
) -> u64 {
    use ev_block_service::store_io::{DesktopTransportError as Transport, Error as Backend};
    use ev_store::Error as StoreError;
    use ev_userspace_contract::block::{DecodeError, Response as BlockResponse};
    let store = match error {
        StoreError::Io(_) => 0u64,
        StoreError::InvalidDeadline => 1,
        StoreError::Capacity => 2,
        StoreError::NotBlank => 3,
        StoreError::Unformatted => 4,
        StoreError::Corrupt => 5,
        StoreError::Unsupported => 6,
        StoreError::InvalidRequest => 7,
        StoreError::Conflict => 8,
        StoreError::StaleOperation => 9,
        StoreError::OutOfOrder => 10,
        StoreError::Phase => 11,
        StoreError::UnknownObject => 12,
        StoreError::NoSpace => 13,
        StoreError::Exhausted => 14,
        StoreError::StaleHealth => 15,
        StoreError::NeedsRecovery => 16,
        StoreError::RecoveryRequired => 17,
    };
    let (backend, detail) = match error {
        StoreError::Io(Backend::Bounds) => (1u64, 0),
        StoreError::Io(Backend::Deadline) => (2, 0),
        StoreError::Io(Backend::NeedsRecovery) => (3, 0),
        StoreError::Io(Backend::Transport(Transport::Clock)) => (0x41, 0),
        StoreError::Io(Backend::Transport(Transport::Deadline)) => (0x42, 0),
        StoreError::Io(Backend::Transport(Transport::BusyBudget)) => (0x43, 0),
        StoreError::Io(Backend::Transport(Transport::Abi)) => (0x44, 0),
        StoreError::Io(Backend::Transport(Transport::Sync(rt::SyncError::Status(value)))) => {
            (0x45, u32::try_from(*value).unwrap_or(u32::MAX))
        }
        StoreError::Io(Backend::Transport(Transport::Sync(
            rt::SyncError::UnexpectedCapability(_),
        ))) => (0x46, 0),
        StoreError::Io(Backend::Decode(value)) => (
            5,
            match value {
                DecodeError::Length => 1,
                DecodeError::Magic => 2,
                DecodeError::Version => 3,
                DecodeError::Opcode => 4,
                DecodeError::Reserved => 5,
                DecodeError::ErrorCode => 6,
            },
        ),
        StoreError::Io(Backend::UnexpectedReply(BlockResponse::Error { code })) => (0x61, *code),
        StoreError::Io(Backend::UnexpectedReply(BlockResponse::Read { sector })) => (0x62, *sector),
        StoreError::Io(Backend::UnexpectedReply(BlockResponse::Written { sector })) => {
            (0x63, *sector)
        }
        StoreError::Io(Backend::UnexpectedReply(BlockResponse::Flushed)) => (0x64, 0),
        StoreError::Io(Backend::Counter) => (7, 0),
        StoreError::Io(Backend::Busy) => (8, 0),
        _ => (0, 0),
    };
    // Prototype failure evidence only. No recovery/success is claimed. Remote
    // statuses beyond u32 use its explicit MAX marker; raw handles are omitted.
    (640u64 << 48) | (store << 40) | (backend << 32) | u64::from(detail)
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
    let retry_stop = if stop == 0 {
        rt::execution::deadline(stop, now(), 512).unwrap_or_else(|_| rt::exit(643))
    } else {
        stop
    };
    loop {
        require(now() < retry_stop, 643);
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
    require(
        rt::execution::validate(stop, now(), cfg!(feature = "native-session")).is_ok(),
        352,
    );
    let caps = ev_file_service::desktop_startup(bytes).unwrap_or_else(|_| rt::exit(646));
    let io = Window::at(record, 1);
    let app = Window::at(record, 2);
    io.guards(512);
    app.guards(256);
    let deadline = rt::execution::deadline(stop, now(), if stop == 0 { 8192 } else { 512 })
        .unwrap_or_else(|_| rt::exit(647));
    require(rt::execution::live(stop, now()), 648);
    let transport = if stop == 0 {
        DesktopEndpoint::for_session_transactions(caps.block)
    } else {
        DesktopEndpoint::new(caps.block, stop)
    }
    .unwrap_or_else(|| rt::exit(649));
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
        require(rt::execution::live(stop, now()), 655);
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
            if stop == 0 && !rt::execution::accepts_deadline(0, now(), inherited.value, 8192) {
                // Quiescence ACK only; the cancelled caller receives its
                // canonical terminal status, never this response as success.
                rt::discipline::reply(route, *b"FME1\x01\0\0\0", received.nonce)
                    .unwrap_or_else(|_| rt::exit(659));
                continue;
            }
            require(
                inherited.status == 0
                    && inherited.capability == 0
                    && rt::execution::accepts_deadline(
                        stop,
                        now(),
                        inherited.value,
                        if stop == 0 { 8192 } else { 1024 },
                    ),
                657,
            );
            let reply = if received.bytes == CALL {
                #[cfg(feature = "native-session")]
                let response = app.client_frame(|private| {
                    match gateway.handle_frame(route, private, inherited.value) {
                        Ok(value) => value,
                        Err(error) => Response::Error { code: error.code() },
                    }
                });
                #[cfg(not(feature = "native-session"))]
                let response = {
                    app.guards(256);
                    let private = app.load();
                    match gateway.handle_frame(route, &private, inherited.value) {
                        Ok(value) => value,
                        Err(error) => Response::Error { code: error.code() },
                    }
                };
                app.publish(&response.encode());
                #[cfg(not(feature = "native-session"))]
                app.guards(256);
                REPLY
            } else {
                match MetadataQuery::decode(received.bytes) {
                    Ok(query) if route == caps.notes_ro || route == caps.private_ro => {
                        // No AppFile memory load/store on this path. A session
                        // child transport returns only after its actual memory
                        // credit has quiesced; preserve the Store/backend poison
                        // and ACK an explicit FME1 failure instead of killing File.
                        let word = gateway.metadata_word(route, query, inherited.value);
                        #[cfg(not(feature = "native-session"))]
                        {
                            word.unwrap_or_else(|_| rt::exit(658)).to_le_bytes()
                        }
                        #[cfg(feature = "native-session")]
                        {
                            match word {
                                Ok(value) => value.to_le_bytes(),
                                Err(error) => {
                                    let code = (error.code() as u16).to_le_bytes();
                                    [b'F', b'M', b'E', b'1', code[0], code[1], 0, 0]
                                }
                            }
                        }
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
