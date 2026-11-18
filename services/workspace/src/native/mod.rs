//! Actual V5 actor boundary. Kernel origin, mapping and RPC credit remain
//! separate from wire IDs. No window access precedes serving-origin checks.
mod diagnostic;
mod legacy;
mod origin;
mod resident;
mod window;

use ev_block_service::{store_io::DesktopEndpoint, workspace::Region};
use ev_userspace_contract::{
    file_v2 as file,
    root_v5::{child, graph::Child, resources},
    syscall, workspace as namespace,
};
use ev_userspace_runtime as rt;
use ev_workspace_service::{
    BindError, Binding, Caller, Captured, Dispatch, EndpointId, Gateway, Loan, NamespaceBinding,
    NamespaceDispatch, NamespaceKey, NamespaceRights, RetireError, backend::Key as BackendKey,
    control, legacy as original,
};
use ev_workspace_store::{Dataset, ObjectId, SectorIo};
use origin::Origin;
use sha2::{Digest, Sha256};
use window::Window;

const BASE: u64 = 1 << 39;
const READY: [u8; 8] = *b"EVWSRDY1";
type Device = diagnostic::Device;
pub(super) fn require(value: bool, code: u64) {
    if !value {
        rt::exit(code);
    }
}
pub(super) fn now() -> u64 {
    let r = rt::monotonic();
    require(
        r.status == 0 && r.capability == 0 && r.value != u64::MAX,
        1200,
    );
    r.value
}
fn yield_now() {
    let r = rt::yield_now();
    require(r.status == 0 && r.value == 0 && r.capability == 0, 1201);
}
fn deadline() -> u64 {
    rt::execution::deadline(0, now(), 8192).unwrap_or_else(|_| rt::exit(1202))
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Copy)]
struct Installed {
    key: BackendKey,
    binding: Binding,
    thread: u64,
    grant_request: u64,
    revoked: bool,
}
#[derive(Clone, Copy)]
struct NamespaceSession {
    binding: NamespaceBinding,
    thread: u64,
    key: NamespaceKey,
    revoked: bool,
}
#[derive(Clone, Copy)]
struct ControlCache {
    process: u64,
    thread: u64,
    token: u64,
    request: u64,
    fingerprint: [u8; 32],
    response: [u8; 256],
}
#[derive(Clone, Copy)]
struct Incoming {
    receiver: u64,
    nonce: u64,
    request: u64,
    origin: Origin,
}

fn receive(receiver: u64) -> Option<Incoming> {
    let r = rt::call4(syscall::RECEIVE_RPC, receiver, 0, 0, 0);
    if r.status == 2 && r.value == 0 && r.capability == 0 && r.serial == 0 {
        return None;
    }
    require(r.status == 0 && r.capability == 0 && r.serial != 0, 1240);
    let Some(origin) = origin::capture(receiver, r.serial) else {
        quarantine();
    };
    Some(Incoming {
        receiver,
        nonce: r.serial,
        request: r.value,
        origin,
    })
}
fn reply(incoming: Incoming) {
    let r = rt::call4(
        syscall::REPLY_RPC,
        incoming.receiver,
        incoming.request,
        0,
        incoming.nonce,
    );
    if r.status != 0 || r.value != 0 || r.capability != 0 || r.serial != 0 {
        quarantine();
    }
}
fn confirm(incoming: Incoming) {
    let Some(current) = origin::capture(incoming.receiver, incoming.nonce) else {
        quarantine();
    };
    if !current.same_call(incoming.origin) || !current.live() {
        quarantine();
    }
}
/// No retry, frame reuse, fabricated cancellation or automatic recovery follows
/// unknown execution. Root must prove independent actor/device retirement.
fn quarantine() -> ! {
    loop {
        yield_now();
    }
}
fn open<'a>(device: Device, scratch: &'a mut ev_workspace_store::Scratch) -> Dataset<'a, Device> {
    #[cfg(feature = "provision-new")]
    {
        // Distinct measured NEW-only image. Never fallback from open failure.
        let id = ev_workspace_store::DatasetId::new([0x84; 16]).unwrap();
        let mut pending = ev_workspace_store::Provisioning::new(device, scratch, id)
            .unwrap_or_else(|_| rt::exit(1241));
        loop {
            let cut = deadline();
            let progress = pending
                .scan_step(128, cut)
                .unwrap_or_else(|_| rt::exit(1242));
            if progress.verified_sectors == progress.total_sectors {
                return pending.finish(cut).unwrap_or_else(|_| rt::exit(1243));
            }
            yield_now();
        }
    }
    #[cfg(not(feature = "provision-new"))]
    {
        let value = Dataset::open(device, scratch, deadline()).unwrap_or_else(|_| rt::exit(1244));
        // Metadata-only open is never an implicit write-repair. A distinct
        // owner recovery phase must finish a cold interrupted mirror first.
        require(!value.needs_mirror_recovery(), 1245);
        value
    }
}
fn send_ready(endpoint: u64) {
    let cut = now().checked_add(512).unwrap_or_else(|| rt::exit(1246));
    loop {
        require(now() < cut, 1247);
        let r = rt::send(endpoint, READY);
        if r.status == 0 {
            require(r.value == 0 && r.capability == 0, 1248);
            return;
        }
        require(r.status == 2 && r.value == 0 && r.capability == 0, 1249);
        yield_now();
    }
}
fn denied(request: u64, decoded: Option<file::Request>) -> [u8; 256] {
    let operation_id = decoded
        .filter(|r| r.request_id == request)
        .map_or(0, |r| r.operation_id);
    file::Response {
        request_id: request,
        operation_id,
        outcome: namespace::Outcome::Denied,
        revision: 0,
        transfer_id: 0,
        offset: 0,
        length: 0,
        file_length: 0,
        digest: [0; 32],
    }
    .encode()
    .unwrap_or([0; 256])
}
fn control_error(request: u64, lease: u64) -> [u8; 256] {
    control::Response {
        request_id: request,
        lease_epoch: if lease != 0 && lease != u64::MAX {
            lease
        } else {
            1
        },
        status: control::Status::Malformed,
    }
    .encode()
    .unwrap_or([0; 256])
}
fn control_response(
    request: control::Request,
    status: control::Status,
    metadata: Option<original::Metadata>,
) -> [u8; 256] {
    if matches!(request.command, control::Command::LegacyInspect { .. }) {
        control::LegacyResponse {
            request_id: request.request_id,
            lease_epoch: request.lease_epoch(),
            status,
            metadata,
        }
        .encode()
        .unwrap()
    } else if matches!(request.command, control::Command::BindContract { .. }) {
        control::BindContractResponse::loaded(request, status)
            .unwrap()
            .encode()
            .unwrap()
    } else if matches!(request.command, control::Command::FileContract { .. }) {
        control::FileContractResponse::loaded(request, status)
            .unwrap()
            .encode()
            .unwrap()
    } else {
        control::Response {
            request_id: request.request_id,
            lease_epoch: request.lease_epoch(),
            status,
        }
        .encode()
        .unwrap()
    }
}

fn namespace_exchange<D: SectorIo>(
    gateway: &mut Gateway<'_, '_, D>,
    session: &mut Option<NamespaceSession>,
    boot_epoch: u64,
    incoming: Incoming,
    window: &Window,
    private: &mut [u8; 256],
    events: u64,
) {
    // Admitted role10 has only Files SEND; role16 has only Root SEND. Their
    // actual receiver fixes namespace-only scope/rights independently of the
    // first packet. This row records actual origin for correlation, not trust.
    let caller = Caller::new(incoming.origin.process, incoming.origin.registered).unwrap();
    let binding = NamespaceBinding {
        endpoint: EndpointId::new(incoming.receiver, boot_epoch).unwrap(),
        caller,
        lease_epoch: boot_epoch,
        directory: ObjectId::ROOT,
        rights: NamespaceRights::Manage,
    };
    if gateway.is_sealed() {
        // Terminal refusal below does not create a fresh namespace binding.
    } else if let Some(row) = session {
        if row.revoked || row.binding != binding || row.thread != incoming.origin.thread {
            reply(incoming);
            return;
        }
    } else {
        let Ok(key) = gateway.bind_namespace(binding) else {
            reply(incoming);
            return;
        };
        *session = Some(NamespaceSession {
            binding,
            thread: incoming.origin.thread,
            key,
            revoked: false,
        });
    }
    window.read(0, private);
    let request = namespace::Request::decode(private).ok();
    if request.is_none_or(|r| {
        r.request_id != incoming.request || r.deadline.tick() != incoming.origin.deadline
    }) || !window.control_padding_zero()
    {
        confirm(incoming);
        window.write(0, &[0; 256]);
        reply(incoming);
        return;
    }
    let captured = Captured {
        endpoint: binding.endpoint,
        caller,
        lease_epoch: binding.lease_epoch,
        now: now(),
    };
    match gateway.handle_namespace(captured, private, 0) {
        Ok(NamespaceDispatch::Complete { frame }) => {
            confirm(incoming);
            window.write(0, &frame);
            reply(incoming);
        }
        Ok(NamespaceDispatch::Retained) => {
            diagnostic::emit(
                events,
                incoming.request,
                private[8],
                incoming.origin.deadline,
                gateway.namespace_pending().map_or(0, |p| p.failure),
            );
            quarantine()
        }
        Err(_) => {
            confirm(incoming);
            window.write(0, &[0; 256]);
            reply(incoming);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn root_control<D: SectorIo>(
    gateway: &mut Gateway<'_, '_, D>,
    legacy: &mut legacy::Backend,
    legacy_scratch: &mut original::Scratch,
    installed: &mut [Option<Installed>; 4],
    receivers: [u64; 4],
    boot_epoch: u64,
    incoming: Incoming,
    window: &Window,
    file_windows: &[Window; 4],
    private: &mut [u8; 256],
    cache: &mut Option<ControlCache>,
    namespace_session: &mut Option<NamespaceSession>,
    files_namespace: &mut Option<NamespaceSession>,
    lease_floors: &mut [u64; 4],
    events: u64,
) {
    // Role16 is a different actual receiver from Files namespace10. Its only
    // SEND is installed in Root, with no ordinary DERIVE/TRANSFER path. Origin
    // is captured from this protected receiver/nonce, never a packet Root PID.
    window.read(0, private);
    if &private[..8] == b"EVWSRQ01" {
        namespace_exchange(
            gateway,
            namespace_session,
            boot_epoch,
            incoming,
            window,
            private,
            events,
        );
        return;
    }
    let request = match control::Request::decode(private) {
        Ok(r)
            if r.request_id == incoming.request
                && r.deadline.tick() == incoming.origin.deadline
                && window.control_padding_zero() =>
        {
            r
        }
        _ => {
            let lease = u64::from_le_bytes(private[32..40].try_into().unwrap());
            window.write(0, &control_error(incoming.request, lease));
            reply(incoming);
            return;
        }
    };
    let fingerprint = digest(private);
    if gateway.is_sealed() && !matches!(request.command, control::Command::Quiesce { .. }) {
        let response = control_response(request, control::Status::Denied, None);
        confirm(incoming);
        window.write(0, &response);
        reply(incoming);
        return;
    }
    if let Some(last) = cache
        && (last.process, last.thread, last.token)
            == (
                incoming.origin.process,
                incoming.origin.thread,
                incoming.origin.registered,
            )
        && request.request_id <= last.request
    {
        if request.request_id == last.request && fingerprint == last.fingerprint {
            window.write(0, &last.response);
        } else {
            window.write(0, &control_response(request, control::Status::Stale, None));
        }
        reply(incoming);
        return;
    }
    let mut original_metadata = None;
    let status = match request.command {
        // Dedicated role16 and the captured Root session are checked before
        // this function. Compatibility is descriptive, never readiness/edit
        // authority; answering does not bind, mutate or perform storage I/O.
        control::Command::FileContract { .. } => control::Status::Applied,
        control::Command::Quiesce { .. } => gateway.quiesce(request, now(), legacy.is_fenced()),
        control::Command::Bind(bind) | control::Command::BindContract { bind, .. } => {
            let index = usize::from(bind.slot);
            let requirement =
                if let control::Command::BindContract { requirement, .. } = request.command {
                    Some(requirement)
                } else {
                    None
                };
            if requirement.is_some_and(|r| !r.supported_by(file::SUPPORT)) {
                control::Status::Unavailable
            } else if request.request_id >= u64::from(u32::MAX) {
                // Current actual Kernel44 carries a32-bit nonce; refuse before
                // installation rather than truncate a wider Selection nonce.
                control::Status::Scope
            } else if bind.lease_epoch <= lease_floors[index] {
                control::Status::Stale
            } else if bind.dataset != gateway.dataset_id() {
                control::Status::Scope
            } else if installed[index].is_some() {
                control::Status::Busy
            } else if let Err(error) = BackendKey::check_quiescent(gateway, legacy.is_fenced()) {
                match error {
                    RetireError::Busy => control::Status::Busy,
                    _ => control::Status::Storage,
                }
            } else {
                let binding = Binding {
                    endpoint: EndpointId::new(receivers[index], boot_epoch).unwrap(),
                    caller: Caller::new(bind.target_process, bind.target_registered_token).unwrap(),
                    lease_epoch: bind.lease_epoch,
                    object: ObjectId::new(bind.object.slot, bind.object.generation).unwrap(),
                    rights: bind.rights,
                };
                let bound = if let Some(required) = requirement {
                    gateway.bind_contract(binding, required)
                } else {
                    gateway.bind(binding)
                };
                match bound {
                    Ok(key) => {
                        let selection = if requirement.is_some() {
                            gateway.bound_selection_v2(key, request.request_id, bind.target_thread)
                        } else {
                            gateway.bound_selection(key, request.request_id, bind.target_thread)
                        };
                        match selection {
                            Ok(selection) => {
                                // Root guarantees the old endpoint/window is quiescent
                                // before a new-slot bind. Publication precedes Applied;
                                // the separate actual inbox transfer carries this ID.
                                confirm(incoming);
                                file_windows[index].zero(0, 8192);
                                file_windows[index].write(0, &selection);
                                installed[index] = Some(Installed {
                                    key: BackendKey::Dataset(key),
                                    binding,
                                    thread: bind.target_thread,
                                    grant_request: request.request_id,
                                    revoked: false,
                                });
                                lease_floors[index] = bind.lease_epoch;
                                control::Status::Applied
                            }
                            Err(_) => {
                                if gateway.revoke(key).is_err() {
                                    quarantine();
                                }
                                control::Status::Storage
                            }
                        }
                    }
                    Err(error) => match error {
                        BindError::Unsupported => control::Status::Unavailable,
                        BindError::Stale => control::Status::Stale,
                        BindError::Capacity | BindError::AlreadyBound => control::Status::Busy,
                        BindError::StorageFenced => control::Status::Storage,
                        BindError::Invalid => control::Status::Scope,
                    },
                }
            }
        }
        control::Command::LegacyInspect { object, .. } => {
            match legacy.inspect(object, request.deadline, legacy_scratch) {
                Ok(snapshot) => {
                    original_metadata = Some(snapshot.metadata);
                    control::Status::Applied
                }
                Err(original::Unavailable::Transport | original::Unavailable::Fenced) => {
                    quarantine()
                }
                Err(_) => control::Status::Unavailable,
            }
        }
        control::Command::BindLegacyReadOnly(bind) => {
            let index = usize::from(bind.slot);
            if request.request_id >= u64::from(u32::MAX) {
                control::Status::Scope
            } else if bind.lease_epoch <= lease_floors[index] {
                control::Status::Stale
            } else if installed[index].is_some() {
                control::Status::Busy
            } else if let Err(error) = BackendKey::check_quiescent(gateway, legacy.is_fenced()) {
                match error {
                    RetireError::Busy => control::Status::Busy,
                    _ => control::Status::Storage,
                }
            } else {
                match legacy.inspect(bind.object, request.deadline, legacy_scratch) {
                    Ok(snapshot) if snapshot.metadata == bind.expected => {
                        let selection = bind.selection(request.request_id).unwrap();
                        let binding = Binding {
                            endpoint: EndpointId::new(receivers[index], boot_epoch).unwrap(),
                            caller: Caller::new(bind.target_process, bind.target_registered_token)
                                .unwrap(),
                            lease_epoch: bind.lease_epoch,
                            object: ObjectId::new(
                                bind.expected.identity.projected_object.slot,
                                bind.expected.identity.projected_object.generation,
                            )
                            .unwrap(),
                            rights: ev_workspace_service::Rights::ReadOnly,
                        };
                        confirm(incoming);
                        file_windows[index].zero(0, 8192);
                        file_windows[index].write(0, &selection);
                        installed[index] = Some(Installed {
                            key: BackendKey::Legacy {
                                object: bind.object,
                                metadata: snapshot.metadata,
                            },
                            binding,
                            thread: bind.target_thread,
                            grant_request: request.request_id,
                            revoked: false,
                        });
                        lease_floors[index] = bind.lease_epoch;
                        control::Status::Applied
                    }
                    Ok(_) => control::Status::Stale,
                    Err(original::Unavailable::Transport | original::Unavailable::Fenced) => {
                        quarantine()
                    }
                    Err(_) => control::Status::Unavailable,
                }
            }
        }
        control::Command::Revoke { slot, lease_epoch } => {
            let index = usize::from(slot);
            match installed[index].filter(|r| r.binding.lease_epoch == lease_epoch && !r.revoked) {
                Some(row) => match row.key.revoke(gateway) {
                    Ok(()) => {
                        // Keep the exact old-owner row until separate actual
                        // kernel retirement AND service reconciliation succeed.
                        installed[index].as_mut().unwrap().revoked = true;
                        control::Status::Applied
                    }
                    Err(_) => control::Status::Stale,
                },
                None => control::Status::Stale,
            }
        }
        control::Command::ReconcileFile {
            slot,
            lease_epoch,
            old,
            grant_nonce,
        } => {
            let index = usize::from(slot);
            match installed[index].filter(|row| {
                row.binding.lease_epoch == lease_epoch
                    && row.binding.caller == Caller::new(old.process, old.registered).unwrap()
                    && row.thread == old.thread
                    && row.grant_request == u64::from(grant_nonce)
            }) {
                Some(row) => {
                    // Root is trusted to have checked its independently held
                    // Kernel61 receipt before this call. These wire integers
                    // only match the old installed row; they are not that proof.
                    let revoked = row.revoked || row.key.revoke(gateway).is_ok();
                    if !revoked {
                        control::Status::Stale
                    } else {
                        installed[index].as_mut().unwrap().revoked = true;
                        match row.key.retire_quiescent(
                            gateway,
                            legacy.is_fenced(),
                            request.deadline.tick(),
                        ) {
                            Ok(()) => {
                                installed[index] = None;
                                control::Status::Applied
                            }
                            Err(RetireError::Busy) => control::Status::Busy,
                            Err(RetireError::Uncertain) => control::Status::Uncertain,
                            Err(RetireError::StorageFenced) => control::Status::Storage,
                            Err(RetireError::Active | RetireError::Stale) => control::Status::Stale,
                        }
                    }
                }
                None => control::Status::Stale,
            }
        }
        control::Command::ResetFilesNamespace { lease_epoch, old } => {
            if files_namespace.is_none() {
                // A Files actor can die before its first namespace request.
                // This exact Root-only no-op clears nothing, and still refuses
                // any global pending/fenced work. Only the independent caller
                // retirement proof permits Root to start a new Files actor.
                match gateway.check_namespace_quiescent() {
                    Ok(()) => control::Status::Applied,
                    Err(RetireError::Busy) => control::Status::Busy,
                    Err(_) => control::Status::Storage,
                }
            } else {
                match files_namespace.filter(|row| {
                    row.binding.lease_epoch == lease_epoch
                        && row.binding.caller == Caller::new(old.process, old.registered).unwrap()
                        && row.thread == old.thread
                }) {
                    Some(row) => {
                        // Explicit Root-only transition AFTER old actual Files is
                        // stopped and its caller/endpoint loans drained. No ordinary
                        // first-caller packet can reset this retained namespace row.
                        let revoked = row.revoked || gateway.revoke_namespace(row.key).is_ok();
                        if !revoked {
                            control::Status::Stale
                        } else {
                            files_namespace.as_mut().unwrap().revoked = true;
                            match gateway.retire_namespace_quiescent(row.key) {
                                Ok(()) => {
                                    *files_namespace = None;
                                    control::Status::Applied
                                }
                                Err(RetireError::Busy) => control::Status::Busy,
                                Err(RetireError::Uncertain) => control::Status::Uncertain,
                                Err(RetireError::StorageFenced) => control::Status::Storage,
                                Err(RetireError::Active | RetireError::Stale) => {
                                    control::Status::Stale
                                }
                            }
                        }
                    }
                    None => control::Status::Stale,
                }
            }
        }
    };
    let response = control_response(request, status, original_metadata);
    *cache = Some(ControlCache {
        process: incoming.origin.process,
        thread: incoming.origin.thread,
        token: incoming.origin.registered,
        request: request.request_id,
        fingerprint,
        response,
    });
    confirm(incoming);
    window.write(0, &response);
    reply(incoming);
}

pub fn run(record: u64, length: u64, stop: u64) -> ! {
    require(
        stop == 0
            && length == child::SIZE as u64
            && record == BASE + resources::STARTUP_PAGE * 4096,
        1250,
    );
    // SAFETY: exact V5 readonly startup extent and fixed retained startup page;
    // the independently checked loader owns its actual mapping and lifetime.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    let profile = child::Profile::parse(Child::Workspace, bytes).unwrap_or_else(|_| rt::exit(1251));
    let context = profile.context();
    let caps: [u64; 16] = core::array::from_fn(|i| profile.handle(i as u64 + 1).unwrap());
    for grant in profile.grants() {
        let r = rt::inspect(grant.handle, u64::from(grant.rights));
        require(r.status == 0 && r.value == 0 && r.capability == 0, 1252);
    }
    require(rt::execution::validate(stop, now(), true).is_ok(), 1253);
    origin::negotiate();
    for receiver in [caps[9], caps[10], caps[11], caps[12], caps[13], caps[15]] {
        let r = rt::call(syscall::BIND_RECEIVER, receiver, 0, 0);
        require(r.status == 0 && r.value == 0 && r.capability == 0, 1254);
    }
    let memory = resident::claim();
    let transport =
        DesktopEndpoint::for_session_transactions(caps[3]).unwrap_or_else(|| rt::exit(1255));
    let backend = diagnostic::Device::new(
        Region::new(transport, Window::at(506, 1)).unwrap_or_else(|| rt::exit(1256)),
    );
    require(
        backend.sectors() == ev_workspace_store::REQUIRED_SECTORS,
        1257,
    );
    let dataset = open(backend, &mut memory.store);
    let mut gateway = Gateway::new(dataset, &mut memory.gateway);
    // Existing role1/page508 and role2 belong exclusively to this owner for
    // the actor's lifetime. There is no reopen/reset or second region owner.
    let mut legacy = legacy::open(caps[1]);
    let root_window = Window::at(494, 2);
    let windows: [Window; 4] = core::array::from_fn(|i| Window::at(496 + i as u64 * 2, 2));
    let receivers = [caps[10], caps[11], caps[12], caps[13]];
    let mut installed: [Option<Installed>; 4] = [None; 4];
    let mut cache = None;
    let mut root_namespace = None;
    let mut files_namespace = None;
    let mut lease_floors = [0; 4];
    let mut root_origin: Option<origin::RootSession> = None;
    send_ready(caps[14]);
    loop {
        if let Some(incoming) = receive(caps[15]) {
            if !incoming.origin.live()
                || incoming.origin.registered != context.incarnation
                || root_origin.is_some_and(|session| !session.matches(incoming.origin))
            {
                reply(incoming);
            } else {
                root_origin.get_or_insert_with(|| origin::RootSession::new(incoming.origin));
                root_control(
                    &mut gateway,
                    &mut legacy,
                    &mut memory.legacy,
                    &mut installed,
                    receivers,
                    context.epoch,
                    incoming,
                    &root_window,
                    &windows,
                    &mut memory.control,
                    &mut cache,
                    &mut root_namespace,
                    &mut files_namespace,
                    &mut lease_floors,
                    caps[14],
                );
            }
        }
        // Ordinary Files namespace has only scoped metadata mutations. It is
        // never an alias for Root bind/control or File contents access.
        if let Some(incoming) = receive(caps[9]) {
            if !incoming.origin.live() {
                reply(incoming);
            } else {
                namespace_exchange(
                    &mut gateway,
                    &mut files_namespace,
                    context.epoch,
                    incoming,
                    &windows[0],
                    &mut memory.control,
                    caps[14],
                );
            }
        }
        for index in 0..4 {
            let Some(incoming) = receive(receivers[index]) else {
                continue;
            };
            let Some(row) = installed[index].filter(|row| {
                !row.revoked
                    && row.binding.caller
                        == Caller::new(incoming.origin.process, incoming.origin.registered).unwrap()
                    && row.thread == incoming.origin.thread
            }) else {
                reply(incoming);
                continue;
            };
            if !incoming.origin.live() {
                reply(incoming);
                continue;
            }
            // Only after current protected identity/thread/lease matching may
            // this caller's mapped window be copied into private residents.
            windows[index].read(0, &mut memory.control);
            let decoded = file::Request::decode(&memory.control).ok();
            let Some(request) = decoded.filter(|r| {
                r.request_id == incoming.request
                    && r.deadline.tick() == incoming.origin.deadline
                    && windows[index].control_padding_zero()
            }) else {
                windows[index].write(0, &denied(incoming.request, decoded));
                reply(incoming);
                continue;
            };
            let captured = Captured {
                endpoint: row.binding.endpoint,
                caller: row.binding.caller,
                lease_epoch: row.binding.lease_epoch,
                now: now(),
            };
            if gateway.is_sealed() {
                // No new ordinary read/mutation may enter either backend after
                // the terminal Root seal, including original readonly Files.
                confirm(incoming);
                windows[index].write(0, &denied(incoming.request, Some(request)));
                reply(incoming);
                continue;
            }
            if let BackendKey::Legacy { object, metadata } = row.key {
                // The backend comes only from retained Root-installed state.
                // Never copy a mutator's bulk window before readonly refusal.
                let length = match request.method {
                    file::Method::Read { length, .. } => length as usize,
                    _ => 0,
                };
                let response = match legacy.file2_read(
                    object,
                    metadata,
                    request,
                    captured.now,
                    &mut memory.legacy,
                    &mut memory.bulk[..length],
                ) {
                    Ok(response) => response,
                    Err(original::ReadError::Unavailable(
                        original::Unavailable::Transport | original::Unavailable::Fenced,
                    )) => quarantine(),
                    Err(_) => {
                        confirm(incoming);
                        windows[index].zero(4096, 4096);
                        windows[index].write(0, &denied(incoming.request, Some(request)));
                        reply(incoming);
                        continue;
                    }
                };
                confirm(incoming);
                windows[index].zero(4096, 4096);
                if response.outcome == namespace::Outcome::Completed && response.length != 0 {
                    windows[index].write(4096, &memory.bulk[..response.length as usize]);
                }
                windows[index].write(0, &response.encode().unwrap());
                reply(incoming);
                continue;
            }
            let loan = match request.method {
                file::Method::Read { length, .. } => {
                    Loan::Read(&mut memory.bulk[..length as usize])
                }
                file::Method::WriteChunk { length, .. } => {
                    windows[index].read(4096, &mut memory.bulk[..length as usize]);
                    Loan::Write(&memory.bulk[..length as usize])
                }
                _ => Loan::None,
            };
            let mut result = match gateway.handle(captured, &memory.control, 0, loan) {
                Ok(r) => r,
                Err(_) => {
                    windows[index].write(0, &denied(incoming.request, Some(request)));
                    reply(incoming);
                    continue;
                }
            };
            loop {
                match result {
                    Dispatch::Complete { frame, read_bytes } => {
                        confirm(incoming);
                        if read_bytes != 0 {
                            windows[index].write(4096, &memory.bulk[..read_bytes as usize]);
                            windows[index]
                                .zero(4096 + read_bytes as usize, 4096 - read_bytes as usize);
                        }
                        windows[index].write(0, &frame);
                        reply(incoming);
                        break;
                    }
                    Dispatch::Retained { .. } => quarantine(),
                    Dispatch::Accepted { .. } => {
                        yield_now();
                        let Some(current) = origin::capture(incoming.receiver, incoming.nonce)
                        else {
                            quarantine();
                        };
                        if !current.same_call(incoming.origin) || !current.live() {
                            quarantine();
                        }
                        result = gateway.poll_commit(now()).unwrap_or_else(|_| quarantine());
                    }
                }
            }
        }
        yield_now();
    }
}
