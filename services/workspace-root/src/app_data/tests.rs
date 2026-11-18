extern crate std;
#[path = "session_tests.rs"]
mod session;
use super::*;
use descriptor::{Descriptor, data_creation, registry_creation};
use ev_app_registry::app_data::AppDataEnvelope;
use ev_store::{BootPolicy, ObjectId, Request as StoreRequest};
use ev_userspace_contract::block::Request;
use ev_zion::AppId;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc, vec::Vec};
struct Media {
    physical: BTreeMap<u32, Sector>,
    window: Sector,
    calls: Vec<Request>,
    fail_write: Option<usize>,
    writes: usize,
}
impl Media {
    fn new() -> Self {
        let physical = [
            16, 32, 64, 80, 96, 112, 128, 256, 8191, 16384, 168705, 168706, 168719, 168734, 168735,
            168750, 168751, 196607,
        ]
        .into_iter()
        .map(|lba| (lba, [0xa5; 512]))
        .collect();
        Self {
            physical,
            window: [0; 512],
            calls: Vec::new(),
            fail_write: None,
            writes: 0,
        }
    }
}
struct Link(Rc<RefCell<Media>>);
struct Buffer(Rc<RefCell<Media>>);
impl Window for Buffer {
    fn load(&self, out: &mut Sector) {
        *out = self.0.borrow().window;
    }
    fn store(&self, bytes: &Sector) {
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
    fn call(&mut self, bytes: [u8; 8], _: u64) -> Result<[u8; 8], ()> {
        let request = Request::decode(&bytes).unwrap();
        let mut m = self.0.borrow_mut();
        m.calls.push(request);
        match request {
            Request::Read { sector } => {
                let physical = ev_block_service::workspace::system_physical_sector(sector).unwrap();
                m.window = *m.physical.get(&physical).unwrap_or(&[0; 512]);
            }
            Request::Write { sector } => {
                let physical = ev_block_service::workspace::system_physical_sector(sector).unwrap();
                let bytes = m.window;
                m.physical.insert(physical, bytes);
                m.writes += 1;
                if m.fail_write == Some(m.writes) {
                    return Err(());
                }
            }
            Request::Flush => (),
        }
        Ok(request.success().encode())
    }
}
fn owner(media: &Rc<RefCell<Media>>) -> Owner<Link, Buffer> {
    Owner::new(Link(media.clone()), Buffer(media.clone())).unwrap()
}
fn prepare(owner: &mut Owner<Link, Buffer>, app: AppId) {
    let initial = AppDataEnvelope::initial(app, 1, 0).unwrap().encode();
    // Host-only explicit fresh allocation fixture. This is NOT an installer or
    // a substitute for actual protected Root enrollment/blank-allocation proof.
    assert!(
        Store::format_new(
            owner.read_write(Region::ExternalAppData),
            data_creation(),
            &initial,
            BootPolicy::new(1).unwrap(),
            8000
        )
        .is_ok()
    );
}
#[test]
fn fixed_descriptor_is_stable_independent_of_package_app_and_separate_from_registry() {
    let a = Descriptor::for_enrolled_app(AppId::new([1; 16]).unwrap(), 1).unwrap();
    let b = Descriptor::for_enrolled_app(AppId::new([2; 16]).unwrap(), 1).unwrap();
    assert_eq!(a.data().creation(), b.data().creation());
    assert_ne!(a.app(), b.app());
    assert_ne!(data_creation(), registry_creation());
    assert!(Descriptor::for_enrolled_app(a.app(), 0).is_none());
    assert!(Descriptor::for_enrolled_app(a.app(), 2).is_none());
}
#[test]
fn checked_private_read_replace_and_independent_cold_use_only_new_closed_region() {
    let media = Rc::new(RefCell::new(Media::new()));
    let preserved = media.borrow().physical.clone();
    let app = AppId::new([9; 16]).unwrap();
    let allocation = Descriptor::for_enrolled_app(app, 1).unwrap().data();
    let mut active = owner(&media);
    assert!(media.borrow().calls.is_empty());
    prepare(&mut active, app);
    {
        let mut data = active
            .open_app_data_checked(allocation, Access::ReadWrite, 8000)
            .unwrap_or_else(|_| panic!("open"));
        assert_eq!(data.read(8000).unwrap().value(), 0);
        let actual = data.replace(0, 73, 8000).unwrap();
        assert_eq!(
            (
                actual.app(),
                actual.schema_epoch(),
                actual.counter(),
                actual.value()
            ),
            (app, 1, 1, 73)
        );
    }
    drop(active);
    let calls = media.borrow().calls.len();
    let mut cold = owner(&media);
    {
        let mut data = cold
            .open_app_data_checked(allocation, Access::ReadOnly, 8000)
            .unwrap_or_else(|_| panic!("cold"));
        assert_eq!(data.read(8000).unwrap().value(), 73);
    }
    let m = media.borrow();
    assert!(
        m.calls[calls..]
            .iter()
            .all(|r| matches!(r, Request::Read { .. }))
    );
    for (lba, bytes) in preserved {
        assert_eq!(m.physical.get(&lba), Some(&bytes));
    }
    for request in &m.calls {
        match request {
            Request::Read { sector } | Request::Write { sector } => {
                assert!((8208..8222).contains(sector))
            }
            Request::Flush => (),
        }
    }
}
#[test]
fn foreign_pending_envelope_is_rejected_before_any_recovery_publication_and_originals_stay_exact() {
    let media = Rc::new(RefCell::new(Media::new()));
    let app = AppId::new([9; 16]).unwrap();
    let mut active = owner(&media);
    prepare(&mut active, app);
    {
        let mut store = active
            .open_mutable_namespace(
                Region::ExternalAppData,
                Access::ReadWrite,
                &data_creation(),
                8000,
            )
            .unwrap_or_else(|_| panic!("host fixture"));
        let pending = AppDataEnvelope::initial(AppId::new([7; 16]).unwrap(), 1, 88)
            .unwrap()
            .encode();
        {
            let mut m = media.borrow_mut();
            m.fail_write = Some(m.writes + 2);
        }
        let op = store.next_operation().unwrap();
        assert!(
            store
                .execute(
                    op,
                    StoreRequest::WriteMutable {
                        object: ObjectId::user_data(),
                        bytes: &pending
                    },
                    8000
                )
                .is_err()
        );
    }
    assert!(matches!(active.status().phase, Phase::Retained(_)));
    drop(active);
    let before = media.borrow().physical.clone();
    let calls = media.borrow().calls.len();
    let mut cold = owner(&media);
    let allocation = Descriptor::for_enrolled_app(app, 1).unwrap().data();
    let error = cold
        .open_app_data_checked(allocation, Access::ReadWrite, 8000)
        .err()
        .expect("foreign pending");
    assert_eq!(error.error, ev_store::Error::Conflict);
    let m = media.borrow();
    assert_eq!(m.physical, before);
    assert!(
        m.calls[calls..]
            .iter()
            .all(|r| matches!(r, Request::Read { .. }))
    );
}

#[test]
fn storage_metadata_does_not_advertise_an_unloaded_nd_handler() {
    let contracts = crate::requirements::LoadedContracts {
        semantic_tree: true,
        file: None,
    };
    assert!(
        ev_zion::Contracts::supported(&contracts, ev_userspace_contract::app_data::INTERFACE, 1)
            .is_none()
    );
}
