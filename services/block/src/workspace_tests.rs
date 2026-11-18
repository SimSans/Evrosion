extern crate std;
use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
    vec::Vec,
};

#[test]
fn exact_receiver_selects_workspace_and_every_legacy_mapping_stays_closed() {
    let routes = Routes::new(101, 102, 103).unwrap();
    assert!(Routes::new(1, 2, 2).is_none());
    assert!(Routes::new(0, 1, 2).is_none());
    for sector in 0..=DISK_SECTORS {
        let request = Request::Read { sector };
        let workspace = routes.resolve(103, request.encode());
        if sector < WORKSPACE_SECTORS {
            let op = workspace.unwrap();
            assert_eq!(op.client, Client::Workspace);
            assert_eq!(
                op.physical,
                Request::Read {
                    sector: WORKSPACE_START + sector
                }
            );
            assert_eq!(op.complete(op.physical.success()), Some(request.success()));
            assert_eq!(
                op.complete(Response::Read {
                    sector: WORKSPACE_START + sector + 1
                }),
                None
            );
        } else {
            assert_eq!(workspace, Err(RouteError::Bounds));
        }
        assert_eq!(
            routes
                .resolve(101, request.encode())
                .ok()
                .map(|o| o.physical),
            system_physical_sector(sector).map(|sector| Request::Read { sector })
        );
        assert_eq!(
            routes
                .resolve(102, request.encode())
                .ok()
                .map(|o| o.physical),
            ev_store::desktop::Client::Files
                .physical_sector(sector)
                .map(|sector| Request::Read { sector })
        );
    }
    for receiver in [0, 104, u64::MAX] {
        assert_eq!(
            routes.resolve(receiver, Request::Flush.encode()),
            Err(RouteError::UnknownEndpoint)
        );
    }
    assert_eq!(
        routes.resolve(103, [0; 8]),
        Err(RouteError::Malformed(DecodeError::Magic))
    );
    assert_eq!(
        routes.resolve(103, Request::Write { sector: u32::MAX }.encode()),
        Err(RouteError::Bounds)
    );
}

#[test]
fn eight_roles_are_strict_and_never_reinterpret_legacy_six_role_startup() {
    use ev_userspace_contract::{Context, Grant, encode};
    let context = Context {
        epoch: 1,
        incarnation: 2,
        process: 3,
        limits: ev_userspace_contract::root_v5::resources::JOB_TEMPLATE_LIMITS[0],
        manifest: [4; 32],
        authority: [5; 32],
    };
    let grants = core::array::from_fn::<_, 8, _>(|i| {
        let (kind, rights) = [
            (7, 3),
            (1, 7),
            (2, 272),
            (1, 7),
            (2, 272),
            (2, 8),
            (1, 7),
            (2, 272),
        ][i];
        Grant {
            selector: i as u64 + 1,
            handle: 300 + i as u64,
            kind,
            rights,
        }
    });
    let bytes = encode(context, &grants).unwrap();
    let caps = startup(&bytes).unwrap();
    assert_eq!(caps.workspace_buffer, 306);
    assert_eq!(caps.workspace_request, 307);
    assert_eq!(
        startup(&encode(context, &grants[..6]).unwrap()),
        Err(StartupError::Count)
    );
    for i in 0..8 {
        let mut wrong = grants;
        wrong[i].rights ^= 128;
        assert_eq!(
            startup(&encode(context, &wrong).unwrap()),
            Err(StartupError::Authority)
        );
        if i > 0 {
            let mut wrong = grants;
            wrong[i].handle = grants[0].handle;
            assert_eq!(
                startup(&encode(context, &wrong).unwrap()),
                Err(StartupError::Authority)
            );
        }
    }
    let mut wrong = context;
    wrong.limits[1] += 1;
    assert_eq!(
        startup(&encode(wrong, &grants).unwrap()),
        Err(StartupError::Limits)
    );
    // Selected profile refinements never widen the old six-role parser or
    // silently accept a retired selected CPU envelope.
    let mut old = context;
    old.limits = ev_userspace_contract::root_v2::catalogue::CHILD_LIMITS;
    assert_eq!(
        startup(&encode(old, &grants).unwrap()),
        Err(StartupError::Limits)
    );
    #[cfg(feature = "test-store-client")]
    {
        assert_eq!(
            crate::desktop::startup(&encode(old, &grants).unwrap()),
            Err(StartupError::Count)
        );
        assert!(crate::desktop::startup(&encode(old, &grants[..6]).unwrap()).is_ok());
    }
}

#[derive(Clone)]
struct Shared {
    window: Rc<RefCell<Sector>>,
    disk: Rc<RefCell<BTreeMap<u32, Sector>>>,
    loads: Rc<Cell<u64>>,
    stores: Rc<Cell<u64>>,
    calls: Rc<RefCell<Vec<(Request, u64)>>>,
}
impl Shared {
    fn new() -> Self {
        Self {
            window: Rc::new(RefCell::new([0; 512])),
            disk: Rc::new(RefCell::new(BTreeMap::new())),
            loads: Rc::new(Cell::new(0)),
            stores: Rc::new(Cell::new(0)),
            calls: Rc::new(RefCell::new(Vec::new())),
        }
    }
}
struct WindowModel(Shared);
impl Window for WindowModel {
    fn load(&self, out: &mut Sector) {
        self.0.loads.set(self.0.loads.get() + 1);
        *out = *self.0.window.borrow();
    }
    fn store(&self, bytes: &Sector) {
        self.0.stores.set(self.0.stores.get() + 1);
        *self.0.window.borrow_mut() = *bytes;
    }
}
#[derive(Clone, Copy)]
enum Reply {
    Good,
    Transport,
    Malformed,
    WrongSector,
}
struct WireModel {
    shared: Shared,
    now: u64,
    reply: Reply,
}
impl Wire for WireModel {
    type Error = u8;
    fn supports_session(&self) -> bool {
        true
    }
    fn capture_session_deadline(&self, deadline: u64) -> Option<u64> {
        (deadline > self.now && deadline - self.now <= 8192)
            .then_some(deadline.min(self.now + 1024))
    }
    fn call(&mut self, bytes: [u8; 8], deadline: u64) -> Result<[u8; 8], u8> {
        let request = Request::decode(&bytes).unwrap();
        self.shared.calls.borrow_mut().push((request, deadline));
        let operation = Routes::new(101, 102, 103)
            .unwrap()
            .resolve(103, bytes)
            .unwrap();
        if matches!(self.reply, Reply::Transport) {
            return Err(7);
        }
        if matches!(self.reply, Reply::Malformed) {
            return Ok([0; 8]);
        }
        if matches!(self.reply, Reply::WrongSector) {
            return Ok(Response::Read { sector: 9 }.encode());
        }
        match operation.physical {
            Request::Read { sector } => {
                *self.shared.window.borrow_mut() =
                    *self.shared.disk.borrow().get(&sector).unwrap_or(&[0; 512])
            }
            Request::Write { sector } => {
                self.shared
                    .disk
                    .borrow_mut()
                    .insert(sector, *self.shared.window.borrow());
            }
            Request::Flush => (),
        }
        Ok(operation.reply.encode())
    }
}
fn region(shared: Shared, reply: Reply) -> Region<WireModel, WindowModel> {
    Region::new(
        WireModel {
            shared: shared.clone(),
            now: 100,
            reply,
        },
        WindowModel(shared),
    )
    .unwrap()
}

#[test]
fn real_sector_adapter_translates_cold_bytes_guards_and_original_deadline() {
    let shared = Shared::new();
    shared
        .disk
        .borrow_mut()
        .insert(WORKSPACE_START - 1, [0x55; 512]);
    shared.disk.borrow_mut().insert(WORKSPACE_END, [0x66; 512]);
    shared.disk.borrow_mut().insert(32, [0x71; 512]);
    let mut device = region(shared.clone(), Reply::Good);
    assert_eq!(device.sectors(), WORKSPACE_SECTORS as u64);
    for local in [0, WORKSPACE_SECTORS as u64 - 1] {
        device.write(local, &[0x83; 512], 8000).unwrap();
        device.flush(8000).unwrap();
    }
    let (wire, window) = device.into_parts();
    let mut cold = Region::new(wire, window).unwrap();
    let mut out = [0; 512];
    cold.read(0, &mut out, 8000).unwrap();
    assert_eq!(out, [0x83; 512]);
    cold.read(WORKSPACE_SECTORS as u64 - 1, &mut out, 8000)
        .unwrap();
    assert_eq!(out, [0x83; 512]);
    assert!(
        shared
            .calls
            .borrow()
            .iter()
            .all(|(_, deadline)| *deadline == 1124)
    );
    assert_eq!(
        shared.disk.borrow().get(&(WORKSPACE_START - 1)),
        Some(&[0x55; 512])
    );
    assert_eq!(shared.disk.borrow().get(&WORKSPACE_END), Some(&[0x66; 512]));
    assert_eq!(shared.disk.borrow().get(&32), Some(&[0x71; 512]));
    let before = (
        shared.calls.borrow().len(),
        shared.loads.get(),
        shared.stores.get(),
    );
    for bad in [WORKSPACE_SECTORS as u64, u64::MAX] {
        assert_eq!(cold.write(bad, &[0; 512], 8000), Err(IoError::Bounds));
    }
    for bad in [0, 100, 8293, u64::MAX] {
        assert_eq!(cold.read(0, &mut out, bad), Err(IoError::Deadline));
    }
    assert_eq!(
        (
            shared.calls.borrow().len(),
            shared.loads.get(),
            shared.stores.get()
        ),
        before
    );
}

#[test]
fn accepted_transport_or_reply_failure_fences_window_and_never_retries() {
    for reply in [Reply::Transport, Reply::Malformed, Reply::WrongSector] {
        let shared = Shared::new();
        let mut device = region(shared.clone(), reply);
        assert!(device.write(0, &[0x91; 512], 8000).is_err());
        assert!(device.is_poisoned());
        let before = (
            shared.calls.borrow().len(),
            shared.loads.get(),
            shared.stores.get(),
        );
        assert_eq!(device.flush(8000), Err(IoError::NeedsRecovery));
        assert_eq!(
            device.read(0, &mut [0; 512], 8000),
            Err(IoError::NeedsRecovery)
        );
        assert_eq!(
            device.write(0, &[0; 512], 8000),
            Err(IoError::NeedsRecovery)
        );
        assert_eq!(
            (
                shared.calls.borrow().len(),
                shared.loads.get(),
                shared.stores.get()
            ),
            before
        );
        assert_eq!(
            before.0, 1,
            "accepted failures cannot trigger fresh attempts"
        );
    }
}

#[test]
fn external_app_regions_are_profile5_root_only_guarded_and_preserve_every_original_mapping() {
    let routes = Routes::new(101, 102, 103).unwrap();
    for region in [ExternalRegion::Registry, ExternalRegion::PrivateData] {
        for local in 0..EXTERNAL_REGION_SECTORS as u64 {
            let wire = region.wire_sector(local).unwrap();
            assert_eq!(
                system_physical_sector(wire),
                Some(region.physical_start() + local as u32)
            );
            assert_eq!(ev_store::network::physical_sector(wire), None);
            assert_eq!(ev_store::native::physical_sector(wire), None);
            assert_eq!(ev_store::native::session_physical_sector(wire), None);
            assert_eq!(
                routes.resolve(102, Request::Read { sector: wire }.encode()),
                Err(RouteError::Bounds)
            );
            // Workspace interprets this integer strictly as its own existing
            // local offset; it cannot select an appended external region.
            assert_eq!(
                routes
                    .resolve(103, Request::Read { sector: wire }.encode())
                    .unwrap()
                    .physical,
                Request::Read {
                    sector: WORKSPACE_START + wire
                }
            );
            assert!(region.physical_start() + local as u32 >= WORKSPACE_END);
        }
        assert_eq!(region.wire_sector(EXTERNAL_REGION_SECTORS as u64), None);
        assert_eq!(region.wire_sector(u64::MAX), None);
    }
    for wire in 0..8192 {
        assert_eq!(
            system_physical_sector(wire),
            ev_store::network::physical_sector(wire)
        );
    }
    for wire in [8206, 8207, 8222, 8223, u32::MAX] {
        assert_eq!(system_physical_sector(wire), None);
    }
    assert_eq!(WORKSPACE_END, 168706);
}
