extern crate std;
use super::*;
use crate::native_plan::{
    state::State,
    storage::{Backend, Error},
};
use ev_block_service::{
    desktop::{Error as RouteError, Routes},
    store_io::{Window, Wire},
};
use ev_content_store::{Arena, Provisioner, TransferCut};
use ev_store::{Sector, SectorIo, network::Area};
use ev_userspace_contract::block::Request;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    vec,
    vec::Vec,
};
const ROOT: u64 = 700;
const FILES: u64 = 701;
#[derive(Clone)]
struct Shared {
    buffer: Rc<RefCell<Sector>>,
    stores: Rc<Cell<usize>>,
    loads: Rc<Cell<usize>>,
}
impl Window for Shared {
    fn load(&self, out: &mut Sector) {
        self.loads.set(self.loads.get() + 1);
        *out = *self.buffer.borrow();
    }
    fn store(&self, b: &Sector) {
        self.stores.set(self.stores.get() + 1);
        *self.buffer.borrow_mut() = *b;
    }
}
#[derive(Clone, Copy)]
enum ReplyMode {
    Logical,
    Physical,
    Malformed,
    Transport,
}
struct Link {
    shared: Shared,
    disk: Rc<RefCell<Vec<Sector>>>,
    durable: Rc<RefCell<Vec<Sector>>>,
    requests: Rc<RefCell<Vec<(Request, Request, u64)>>>,
    mode: ReplyMode,
    captures: Rc<Cell<usize>>,
}
impl Wire for Link {
    type Error = ();
    fn supports_session(&self) -> bool {
        true
    }
    fn capture_session_deadline(&self, deadline: u64) -> Option<u64> {
        self.captures.set(self.captures.get() + 1);
        (deadline > 100 && deadline <= 8292).then_some(deadline.min(1124))
    }
    fn call(&mut self, b: [u8; 8], deadline: u64) -> Result<[u8; 8], ()> {
        let logical = Request::decode(&b).unwrap();
        let op = Routes::new_network(ROOT, FILES)
            .unwrap()
            .resolve(ROOT, b)
            .unwrap();
        self.requests
            .borrow_mut()
            .push((logical, op.physical, deadline));
        if matches!(self.mode, ReplyMode::Transport) {
            return Err(());
        }
        match op.physical {
            Request::Read { sector } => {
                *self.shared.buffer.borrow_mut() = self.disk.borrow()[sector as usize]
            }
            Request::Write { sector } => {
                self.disk.borrow_mut()[sector as usize] = *self.shared.buffer.borrow()
            }
            Request::Flush => self.durable.borrow_mut().clone_from(&self.disk.borrow()),
        }
        match self.mode {
            ReplyMode::Logical => Ok(op.complete(op.physical.success()).unwrap().encode()),
            ReplyMode::Physical => Ok(op.physical.success().encode()),
            ReplyMode::Malformed => Ok([0; 8]),
            ReplyMode::Transport => unreachable!(),
        }
    }
}
struct Fixture {
    backend: Backend<Link, Shared>,
    shared: Shared,
    disk: Rc<RefCell<Vec<Sector>>>,
    durable: Rc<RefCell<Vec<Sector>>>,
    requests: Rc<RefCell<Vec<(Request, Request, u64)>>>,
    captures: Rc<Cell<usize>>,
}
fn fixture(mode: ReplyMode) -> Fixture {
    let shared = Shared {
        buffer: Rc::new(RefCell::new([0; 512])),
        stores: Rc::new(Cell::new(0)),
        loads: Rc::new(Cell::new(0)),
    };
    let mut bytes = vec![[0x98; 512]; 8192];
    for b in &mut bytes[128..142] {
        b.fill(0);
    }
    for b in &mut bytes[256..] {
        b.fill(0);
    }
    let disk = Rc::new(RefCell::new(bytes.clone()));
    let durable = Rc::new(RefCell::new(bytes));
    let requests = Rc::new(RefCell::new(vec![]));
    let captures = Rc::new(Cell::new(0));
    let link = Link {
        shared: shared.clone(),
        disk: disk.clone(),
        durable: durable.clone(),
        requests: requests.clone(),
        mode,
        captures: captures.clone(),
    };
    Fixture {
        backend: Backend::new(link, shared.clone(), 0).unwrap(),
        shared,
        disk,
        durable,
        requests,
        captures,
    }
}
fn metadata() -> ev_content_store::MetadataCut {
    TransferCut::new(100, 100_000)
        .unwrap()
        .metadata(100)
        .unwrap()
}
fn cut() -> ev_content_store::IoCut {
    TransferCut::new(100, 100_000)
        .unwrap()
        .child(100, 1024)
        .unwrap()
}
#[test]
fn every_new_logical_sector_uses_actual_route_same_window_and_logical_ack() {
    let mut f = fixture(ReplyMode::Logical);
    for area in [Area::Checkpoint, Area::Objects] {
        let mut d = f.backend.network_device(area, true);
        for local in 0..area.sectors() {
            let pattern = [local as u8; 512];
            d.write(local, &pattern, 2000).unwrap();
            let mut check = [0; 512];
            d.read(local, &mut check, 2000).unwrap();
            assert_eq!(check, pattern);
        }
    }
    let rows = f.requests.borrow();
    assert_eq!(rows.len(), (14 + 7936) * 2);
    for (logical, physical, deadline) in rows.iter().copied() {
        assert_eq!(deadline, 1124);
        match (logical, physical) {
            (Request::Read { sector: l }, Request::Read { sector: p })
            | (Request::Write { sector: l }, Request::Write { sector: p }) => {
                assert_eq!(ev_store::network::physical_sector(l), Some(p))
            }
            _ => panic!(),
        }
    }
    assert_eq!(f.shared.stores.get(), 7950);
    assert_eq!(f.shared.loads.get(), 7950);
    assert_eq!(f.captures.get(), 15900);
    for (i, b) in f.disk.borrow().iter().enumerate() {
        if !(128..142).contains(&i) && i < 256 {
            assert_eq!(*b, [0x98; 512]);
        }
    }
}
#[test]
fn bounds_consent_and_finite_profile_refuse_before_window_or_rpc() {
    let mut f = fixture(ReplyMode::Logical);
    for area in [Area::Checkpoint, Area::Objects] {
        let mut d = f.backend.network_device(area, false);
        assert_eq!(d.write(0, &[1; 512], 2000), Err(Error::NoConsent));
        assert_eq!(d.flush(2000), Err(Error::NoConsent));
        for local in [area.sectors(), u64::MAX] {
            assert_eq!(d.read(local, &mut [0; 512], 2000), Err(Error::Bounds));
        }
    }
    assert!(f.requests.borrow().is_empty());
    assert_eq!(f.shared.stores.get(), 0);
    assert_eq!(f.shared.loads.get(), 0);
    f.backend.stop = 100;
    assert_eq!(
        f.backend
            .network_device(Area::Objects, true)
            .write(0, &[1; 512], 200),
        Err(Error::NoConsent)
    );
    assert!(f.requests.borrow().is_empty());
}
#[test]
fn wrong_physical_or_malformed_or_unknown_response_poison_before_read_window_and_never_retry() {
    for mode in [
        ReplyMode::Physical,
        ReplyMode::Malformed,
        ReplyMode::Transport,
    ] {
        let mut f = fixture(mode);
        let result = f
            .backend
            .network_device(Area::Objects, true)
            .read(0, &mut [0; 512], 2000);
        assert!(result.is_err());
        assert!(f.backend.poisoned());
        assert_eq!(f.shared.loads.get(), 0);
        let stores = f.shared.stores.get();
        assert_eq!(
            f.backend
                .network_device(Area::Checkpoint, true)
                .write(0, &[8; 512], 2000),
            Err(Error::Recovery)
        );
        assert_eq!(f.requests.borrow().len(), 1);
        assert_eq!(f.shared.stores.get(), stores);
    }
}
#[test]
fn content_gat_adapter_real_store_publish_readback_and_reopen_never_change_old_regions() {
    let mut f = fixture(ReplyMode::Logical);
    let before = f.durable.borrow().clone();
    let manifest = creation_manifest([1; 32], [2; 32]).unwrap();
    let scope = BackendRef::new(&mut f.backend, true);
    let transfer = TransferCut::new(100, 100_000).unwrap();
    let mut p = Provisioner::new(scope, manifest, transfer).unwrap_or_else(|_| panic!());
    let mut steps = 0;
    while p.remaining() != 0 {
        p.scan(cut()).unwrap();
        steps += 1;
    }
    assert_eq!(steps, 994);
    let mut a = p.finish(metadata()).unwrap_or_else(|_| panic!());
    let payload = [0x33; 2011];
    let expected = a.head_digest();
    let mut stage = a
        .begin(
            expected,
            payload.len() as u64,
            Sha256::digest(payload).into(),
            transfer,
            metadata(),
        )
        .unwrap();
    stage.write_chunk(&payload, cut()).unwrap();
    let mut r = stage.seal(cut()).unwrap();
    let mut out = [0; 4096];
    assert_eq!(r.read_chunk(&mut out, cut()).unwrap(), payload.len());
    assert_eq!(&out[..payload.len()], &payload);
    let v = r.finish().unwrap();
    let h = v.current_head();
    let object = v.publish(h, metadata()).unwrap();
    let mut a = Arena::open(a.into_backend(), manifest, metadata()).unwrap_or_else(|_| panic!());
    assert_eq!(a.published_metadata(), Some(object));
    let mut r = a.reader(object, transfer, cut()).unwrap();
    assert_eq!(r.read_chunk(&mut out, cut()).unwrap(), payload.len());
    r.finish().unwrap().release();
    for (i, b) in f.durable.borrow().iter().enumerate() {
        if !(128..142).contains(&i) && !(256..8192).contains(&i) {
            assert_eq!(*b, before[i], "outside {i}");
        }
    }
    for (_, physical, _) in f.requests.borrow().iter() {
        if let Request::Write { sector } = physical {
            assert!((128..142).contains(sector) || (256..8192).contains(sector));
        }
    }
}
#[test]
fn actual_source_state_rejects_content_reborrow_after_backend_uncertainty() {
    let f = fixture(ReplyMode::Transport);
    let mut state = State::new(f.backend);
    {
        let mut scope = state.content_backend(true).unwrap();
        assert!(
            scope
                .device(ev_content_store::Area::Objects)
                .read(0, &mut [0; 512], 2000)
                .is_err()
        );
    }
    assert!(state.recovery_required());
    assert!(state.content_backend(true).is_err());
    assert_eq!(f.requests.borrow().len(), 1);
}
#[test]
fn stable_creation_is_namespace_volume_and_format_bound_without_execution_or_health_claim() {
    let m = creation_manifest([1; 32], [2; 32]).unwrap();
    assert!(m.valid());
    assert_eq!(m.abi, ev_content_store::FORMAT_ABI);
    assert_ne!(m, creation_manifest([3; 32], [2; 32]).unwrap());
    assert_ne!(m, creation_manifest([1; 32], [3; 32]).unwrap());
    assert_eq!(
        creation_manifest([0; 32], [2; 32]),
        Err(CreationError::Namespace)
    );
    assert_eq!(
        creation_manifest([1; 32], [0; 32]),
        Err(CreationError::Volume)
    );
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(ev_content_store::FORMAT_ABI_DESCRIPTION)),
        ev_content_store::FORMAT_ABI
    );
    let mut f = fixture(ReplyMode::Logical);
    let mut p = Provisioner::new(
        BackendRef::new(&mut f.backend, true),
        m,
        TransferCut::new(100, 100_000).unwrap(),
    )
    .unwrap_or_else(|_| panic!());
    while p.remaining() != 0 {
        p.scan(cut()).unwrap();
    }
    let a = p.finish(metadata()).unwrap_or_else(|_| panic!());
    let mut b = a.into_backend();
    let store = ev_store::Store::open_mutable_namespace(
        b.device(ev_content_store::Area::Checkpoint),
        &m,
        1124,
    )
    .unwrap_or_else(|_| panic!());
    assert_eq!(store.known_good(), None);
    assert_eq!(store.committed_boot_serial(), Ok(0));
}
#[test]
fn files_unknown_endpoints_and_old_profiles_cannot_name_new_areas() {
    let r = Routes::new_network(ROOT, FILES).unwrap();
    for area in [Area::Checkpoint, Area::Objects] {
        for local in 0..area.sectors() {
            let wire = area.wire_sector(local).unwrap();
            for request in [
                Request::Read { sector: wire },
                Request::Write { sector: wire },
            ] {
                assert_eq!(r.resolve(FILES, request.encode()), Err(RouteError::Bounds));
                assert_eq!(
                    r.resolve(0, request.encode()),
                    Err(RouteError::UnknownEndpoint)
                );
                assert_eq!(
                    Routes::new_session(ROOT, FILES)
                        .unwrap()
                        .resolve(ROOT, request.encode()),
                    Err(RouteError::Bounds)
                );
            }
        }
    }
}

#[test]
fn owned_content_steps_allow_cached_ui_and_return_only_the_same_actual_backend() {
    let f = fixture(ReplyMode::Logical);
    let before = f.durable.borrow().clone();
    let mut state = State::new(f.backend);
    let old_mutations = state.mutations();
    let owner = state.take_content_backend(true).unwrap();
    assert!(state.content_busy() && state.transition_pending());
    assert!(!state.recovery_required());
    assert!(state.content_backend(true).is_err());
    assert!(state.take_content_backend(true).is_err());
    assert!(matches!(
        state.inspect_system(2000),
        crate::native_diagnostics::system::State::NotCollected
    ));
    assert_eq!(f.requests.borrow().len(), 0);
    let transfer = TransferCut::new(100, 100_000).unwrap();
    let manifest = creation_manifest([1; 32], [2; 32]).unwrap();
    let mut work = Provisioner::new(owner, manifest, transfer).unwrap_or_else(|_| panic!());
    while work.remaining() != 0 {
        work.scan(cut()).unwrap();
        assert!(state.content_busy());
        assert_eq!(state.mutations(), old_mutations);
    }
    let a = work.finish(metadata()).unwrap_or_else(|_| panic!());
    let expected = a.head_digest();
    let payload = [0x35; 2011];
    let mut stage = a
        .begin_owned(
            expected,
            payload.len() as u64,
            Sha256::digest(payload).into(),
            transfer,
            metadata(),
        )
        .unwrap_or_else(|_| panic!());
    stage.write_chunk(&payload, cut()).unwrap();
    let mut reader = stage.seal(cut()).unwrap_or_else(|_| panic!());
    let mut bytes = [0; 4096];
    assert_eq!(reader.read_chunk(&mut bytes, cut()).unwrap(), payload.len());
    assert_eq!(&bytes[..payload.len()], &payload);
    let verified = reader.finish().unwrap_or_else(|_| panic!());
    let expected = verified.current_head();
    let (a, object) = verified
        .publish(expected, metadata())
        .unwrap_or_else(|_| panic!());
    assert_eq!(a.published_metadata(), Some(object));
    assert!(state.restore_content_backend(a.into_backend()).is_ok());
    assert!(!state.content_busy());
    assert!(state.mutations() > old_mutations);
    let after = f.durable.borrow();
    for (index, (old, new)) in before.iter().zip(after.iter()).enumerate() {
        if !(128..142).contains(&index) && !(256..8192).contains(&index) {
            assert_eq!(old, new, "outside {index}");
        }
    }
}
#[test]
fn foreign_owned_backend_return_refuses_without_losing_either_owner_or_resetting_poison() {
    let a = fixture(ReplyMode::Logical);
    let b = fixture(ReplyMode::Transport);
    let mut left = State::new(a.backend);
    let mut right = State::new(b.backend);
    let left_owner = left.take_content_backend(true).unwrap();
    let mut right_owner = right.take_content_backend(true).unwrap();
    assert!(
        right_owner
            .device(ev_content_store::Area::Objects)
            .read(0, &mut [0; 512], 2000)
            .is_err()
    );
    let rejected = left.restore_content_backend(right_owner).err().unwrap();
    assert!(left.content_busy() && right.content_busy());
    assert_eq!(a.requests.borrow().len(), 0);
    assert!(left.restore_content_backend(left_owner).is_ok());
    assert!(right.restore_content_backend(rejected).is_ok());
    assert!(!left.recovery_required());
    assert!(right.recovery_required());
    assert!(right.take_content_backend(true).is_err());
    assert_eq!(b.requests.borrow().len(), 1);
}
