extern crate std;
use super::*;
use crate::{
    app_data::Access,
    development::tests::{effect, facts_for, package},
};
use ev_store::{ObjectId, Request as StoreRequest};
use ev_userspace_contract::block::Request;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc, vec::Vec};

struct Media {
    physical: BTreeMap<u32, [u8; 512]>,
    window: [u8; 512],
    calls: Vec<(Request, u64)>,
    fail_flush: bool,
}
impl Media {
    fn new() -> Self {
        Self {
            physical: [
                16, 32, 64, 80, 96, 112, 128, 256, 8191, 16384, 168705, 168706, 168719, 168734,
                168735, 168750, 168751, 196607,
            ]
            .into_iter()
            .map(|n| (n, [0xa5; 512]))
            .collect(),
            window: [0; 512],
            calls: Vec::new(),
            fail_flush: false,
        }
    }
}
struct Link(Rc<RefCell<Media>>);
struct Buffer(Rc<RefCell<Media>>);
impl Window for Buffer {
    fn load(&self, out: &mut [u8; 512]) {
        *out = self.0.borrow().window;
    }
    fn store(&self, bytes: &[u8; 512]) {
        self.0.borrow_mut().window = *bytes;
    }
}
impl Wire for Link {
    type Error = ();
    fn supports_session(&self) -> bool {
        true
    }
    fn capture_session_deadline(&self, cut: u64) -> Option<u64> {
        (cut > 100 && cut <= 8292).then_some(cut.min(1124))
    }
    fn call(&mut self, bytes: [u8; 8], cut: u64) -> Result<[u8; 8], ()> {
        let request = Request::decode(&bytes).unwrap();
        let mut m = self.0.borrow_mut();
        m.calls.push((request, cut));
        match request {
            Request::Read { sector } => {
                let physical = ev_block_service::workspace::system_physical_sector(sector).unwrap();
                m.window = *m.physical.get(&physical).unwrap_or(&[0; 512]);
            }
            Request::Write { sector } => {
                let physical = ev_block_service::workspace::system_physical_sector(sector).unwrap();
                let bytes = m.window;
                m.physical.insert(physical, bytes);
            }
            Request::Flush if m.fail_flush => {
                m.fail_flush = false;
                return Err(());
            }
            Request::Flush => (),
        }
        Ok(request.success().encode())
    }
}
fn owner(m: &Rc<RefCell<Media>>) -> Owner<Link, Buffer> {
    Owner::new(Link(m.clone()), Buffer(m.clone())).unwrap()
}
fn loaded() -> crate::requirements::LoadedContracts {
    crate::requirements::LoadedContracts {
        semantic_tree: true,
        file: None,
    }
}
fn approval(bytes: &[u8], intent: Intent) -> Approval {
    let f = facts_for(bytes);
    super::super::approve(f, intent, effect(f, intent), 100, 8000).unwrap()
}
fn install(m: &Rc<RefCell<Media>>, bytes: &[u8]) {
    let mut owner = owner(m);
    let mut started = false;
    let mut pending = None;
    allocate(
        &mut owner,
        bytes,
        &PrivateDataContracts::new(&loaded(), true),
        &approval(bytes, Intent::Install),
        &mut started,
        &mut pending,
    )
    .unwrap();
    assert!(started);
    assert!(pending.is_none());
}
fn no_mutation(m: &Rc<RefCell<Media>>, bytes: &[u8]) {
    let before = m.borrow().physical.clone();
    let at = m.borrow().calls.len();
    let mut owner = owner(m);
    let mut pending = None;
    assert!(
        registry(
            &mut owner,
            bytes,
            &PrivateDataContracts::new(&loaded(), true),
            &approval(bytes, Intent::Run),
            true,
            &mut pending
        )
        .is_err()
    );
    let m = m.borrow();
    assert_eq!(m.physical, before);
    assert!(
        m.calls[at..]
            .iter()
            .all(|(r, _)| matches!(r, Request::Read { .. }))
    );
}
#[test]
fn actual_allocation_and_cold_exact_run_preserve_originals_and_private_owner() {
    let m = Rc::new(RefCell::new(Media::new()));
    let originals = m.borrow().physical.clone();
    let bytes = package(9, false, false);
    install(&m, &bytes);
    let mut cold = owner(&m);
    let mut pending = None;
    let run = approval(&bytes, Intent::Run);
    registry(
        &mut cold,
        &bytes,
        &PrivateDataContracts::new(&loaded(), true),
        &run,
        true,
        &mut pending,
    )
    .unwrap();
    let at = m.borrow().calls.len();
    drop(cold);
    let mut cold = owner(&m);
    registry(
        &mut cold,
        &bytes,
        &PrivateDataContracts::new(&loaded(), true),
        &run,
        true,
        &mut pending,
    )
    .unwrap();
    let app = Package::parse(&bytes).unwrap().app().claimed_app;
    {
        let mut data = cold
            .open_app_data_checked(
                descriptor::Descriptor::for_enrolled_app(app, 1)
                    .unwrap()
                    .data(),
                Access::ReadOnly,
                8000,
            )
            .unwrap_or_else(|_| panic!("cold data"));
        let value = data.read(8000).unwrap();
        assert_eq!((value.app(), value.counter(), value.value()), (app, 0, 0));
    }
    let m = m.borrow();
    assert!(
        m.calls[at..]
            .iter()
            .all(|(r, _)| matches!(r, Request::Read { .. }))
    );
    for (sector, bytes) in originals {
        assert_eq!(m.physical.get(&sector), Some(&bytes));
    }
    for (r, cut) in &m.calls {
        assert!(*cut <= 8000);
        if let Request::Read { sector } | Request::Write { sector } = r {
            assert!(
                [Region::ExternalRegistry, Region::ExternalAppData]
                    .into_iter()
                    .any(|region| (0..ev_store::REQUIRED_SECTORS)
                        .any(|local| region.wire_sector(local) == Some(*sector)))
            );
        }
    }
}
#[test]
fn every_nonblank_sector_in_either_region_refuses_before_any_allocation_write() {
    let bytes = package(9, false, false);
    for region in [Region::ExternalRegistry, Region::ExternalAppData] {
        for local in 0..ev_store::REQUIRED_SECTORS {
            let m = Rc::new(RefCell::new(Media::new()));
            m.borrow_mut()
                .physical
                .insert(region.physical_start() + local as u32, [1; 512]);
            let before = m.borrow().physical.clone();
            let mut active = owner(&m);
            let mut started = false;
            let mut pending = None;
            assert_eq!(
                allocate(
                    &mut active,
                    &bytes,
                    &PrivateDataContracts::new(&loaded(), true),
                    &approval(&bytes, Intent::Install),
                    &mut started,
                    &mut pending
                ),
                Err(Failure::Refused)
            );
            assert!(!started);
            assert!(pending.is_none());
            let m = m.borrow();
            assert_eq!(m.physical, before);
            assert!(
                m.calls
                    .iter()
                    .all(|(r, _)| matches!(r, Request::Read { .. }))
            );
        }
    }
}
#[test]
fn changed_package_unloaded_nd_and_uninstalled_run_never_format_or_write() {
    let bytes = package(9, false, false);
    let other = package(8, false, false);
    let m = Rc::new(RefCell::new(Media::new()));
    let mut active = owner(&m);
    let install = approval(&bytes, Intent::Install);
    let mut started = false;
    let mut pending = None;
    for (source, available) in [(&other[..], true), (&bytes[..], false)] {
        assert_eq!(
            allocate(
                &mut active,
                source,
                &PrivateDataContracts::new(&loaded(), available),
                &install,
                &mut started,
                &mut pending
            ),
            Err(Failure::Refused)
        );
    }
    assert!(m.borrow().calls.is_empty());
    assert_eq!(
        registry(
            &mut active,
            &bytes,
            &PrivateDataContracts::new(&loaded(), true),
            &approval(&bytes, Intent::Run),
            true,
            &mut pending
        ),
        Err(Failure::NotInstalled)
    );
    assert!(
        m.borrow()
            .calls
            .iter()
            .all(|(r, _)| matches!(r, Request::Read { .. }))
    );
}
enum Payload {
    Exact,
    ForeignApp,
    CorruptDigest,
}
fn pending_activation(m: &Rc<RefCell<Media>>, bytes: &[u8], payload_kind: Payload) {
    let mut active = owner(m);
    let package = Package::parse(bytes).unwrap();
    let resolver = OnePackage { package };
    let loaded = loaded();
    let contracts = PrivateDataContracts::new(&loaded, true);
    let mut payload = {
        let registry = Registry::open_checked(
            active.read_write(Region::ExternalRegistry),
            policy(&resolver.package),
            &descriptor::registry_creation(),
            &resolver,
            &contracts,
            8000,
        )
        .unwrap_or_else(|_| panic!("fixture registry"));
        registry
            .prepare(
                registry.expected().unwrap(),
                Change::Activate,
                &resolver,
                &contracts,
            )
            .unwrap()
            .after()
            .encode()
    };
    match payload_kind {
        Payload::Exact => (),
        Payload::ForeignApp => {
            payload[16..32].fill(8);
            let mut hash = Sha256::new();
            hash.update(b"evrosion.app-registry.v1\0");
            hash.update(&payload[..224]);
            payload[224..].copy_from_slice(&hash.finalize());
        }
        Payload::CorruptDigest => payload[224] ^= 1,
    }
    let mut store = Store::open(active.read_write(Region::ExternalRegistry), 8000)
        .unwrap_or_else(|_| panic!("fixture store"));
    m.borrow_mut().fail_flush = true;
    let operation = store.next_operation().unwrap();
    assert!(
        store
            .execute(
                operation,
                StoreRequest::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &payload
                },
                8000
            )
            .is_err()
    );
    assert!(matches!(
        active.status().phase,
        crate::app_data::Phase::Retained(_)
    ));
}
#[test]
fn cold_foreign_committed_or_pending_registry_is_refused_before_recovery_writes() {
    let bytes = package(9, false, false);
    let foreign = package(8, false, false);
    let m = Rc::new(RefCell::new(Media::new()));
    install(&m, &bytes);
    no_mutation(&m, &foreign);
    for payload in [Payload::ForeignApp, Payload::CorruptDigest] {
        let m = Rc::new(RefCell::new(Media::new()));
        install(&m, &bytes);
        pending_activation(&m, &bytes, payload);
        no_mutation(&m, &bytes);
    }
}
#[test]
fn cold_exact_pending_activation_recovers_once_and_no_later_open_republishes() {
    let bytes = package(9, false, false);
    let m = Rc::new(RefCell::new(Media::new()));
    install(&m, &bytes);
    pending_activation(&m, &bytes, Payload::Exact);
    let mut cold = owner(&m);
    let mut pending = None;
    let run = approval(&bytes, Intent::Run);
    let at = m.borrow().calls.len();
    registry(
        &mut cold,
        &bytes,
        &PrivateDataContracts::new(&loaded(), true),
        &run,
        true,
        &mut pending,
    )
    .unwrap();
    assert!(
        m.borrow().calls[at..]
            .iter()
            .any(|(r, _)| matches!(r, Request::Write { .. }))
    );
    drop(cold);
    let mut cold = owner(&m);
    let at = m.borrow().calls.len();
    registry(
        &mut cold,
        &bytes,
        &PrivateDataContracts::new(&loaded(), true),
        &run,
        true,
        &mut pending,
    )
    .unwrap();
    assert!(
        m.borrow().calls[at..]
            .iter()
            .all(|(r, _)| matches!(r, Request::Read { .. }))
    );
}
#[test]
fn unknown_allocation_keeps_original_attempt_and_refuses_a_new_storage_call() {
    let bytes = package(9, false, false);
    let m = Rc::new(RefCell::new(Media::new()));
    m.borrow_mut().fail_flush = true;
    let mut active = owner(&m);
    let install = approval(&bytes, Intent::Install);
    let mut started = false;
    let mut pending = None;
    assert_eq!(
        allocate(
            &mut active,
            &bytes,
            &PrivateDataContracts::new(&loaded(), true),
            &install,
            &mut started,
            &mut pending
        ),
        Err(Failure::Retained)
    );
    assert!(started);
    let status = active.status();
    assert!(matches!(status.phase, crate::app_data::Phase::Retained(_)));
    assert_eq!(status.last.unwrap().original_deadline, install.cut());
    let before = m.borrow().physical.clone();
    let count = m.borrow().calls.len();
    assert_eq!(
        allocate(
            &mut active,
            &bytes,
            &PrivateDataContracts::new(&loaded(), true),
            &install,
            &mut started,
            &mut pending
        ),
        Err(Failure::Retained)
    );
    assert_eq!(active.status(), status);
    assert_eq!(m.borrow().calls.len(), count);
    assert_eq!(m.borrow().physical, before);
}
