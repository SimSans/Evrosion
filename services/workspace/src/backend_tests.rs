use super::*;
use crate::{Binding, Caller, Captured, Dispatch, EndpointId, Loan, Rights, Scratch};
use ev_userspace_contract::{
    file_v2 as file,
    workspace::{Deadline, Outcome},
};
use ev_workspace_store::{
    Dataset, DatasetId, Kind, Name, ObjectId, Scratch as StoreScratch, Sector,
};
use std::{boxed::Box, cell::RefCell, collections::BTreeMap, rc::Rc};

const CUT: u64 = 100_000;
#[derive(Default)]
struct State {
    sectors: BTreeMap<u64, Sector>,
    reads: usize,
    writes: usize,
    flushes: usize,
    fail_flush: bool,
}
#[derive(Clone, Default)]
struct Disk(Rc<RefCell<State>>);
impl Disk {
    fn counts(&self) -> (usize, usize, usize) {
        let state = self.0.borrow();
        (state.reads, state.writes, state.flushes)
    }
}
impl SectorIo for Disk {
    type Error = ();
    fn sectors(&self) -> u64 {
        ev_workspace_store::REQUIRED_SECTORS
    }
    fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> Result<(), ()> {
        let mut state = self.0.borrow_mut();
        state.reads += 1;
        *out = *state.sectors.get(&lba).unwrap_or(&[0; 512]);
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> Result<(), ()> {
        let mut state = self.0.borrow_mut();
        state.writes += 1;
        state.sectors.insert(lba, *bytes);
        Ok(())
    }
    fn flush(&mut self, _: u64) -> Result<(), ()> {
        let mut state = self.0.borrow_mut();
        state.flushes += 1;
        if core::mem::take(&mut state.fail_flush) {
            Err(())
        } else {
            Ok(())
        }
    }
}
fn dataset<'a>(disk: Disk, scratch: &'a mut StoreScratch) -> (Dataset<'a, Disk>, ObjectId, u64) {
    let mut dataset = Dataset::format_new(disk, scratch, DatasetId::new([0x84; 16]).unwrap(), CUT)
        .unwrap_or_else(|_| panic!("new owned model Dataset"));
    let receipt = dataset
        .create(
            dataset.next_operation().unwrap(),
            dataset.namespace_revision(),
            ObjectId::ROOT,
            Name::new("model.txt").unwrap(),
            Kind::File,
            CUT,
        )
        .unwrap();
    let revision = dataset.metadata(receipt.object).unwrap().revision;
    (dataset, receipt.object, revision)
}
fn route(object: ObjectId) -> Binding {
    Binding {
        endpoint: EndpointId::new(503, 1).unwrap(),
        caller: Caller::new(0x1_0000_0003, 0).unwrap(),
        lease_epoch: 4,
        object,
        rights: Rights::ReadWrite,
    }
}
fn old_key() -> Key {
    Key::Legacy {
        object: legacy::Object::Notes,
        metadata: legacy::Metadata {
            identity: legacy::Identity::for_object(legacy::Object::Notes),
            counter: 0,
            length: 0,
            digest: crate::hash(&[]),
            global_operation: 0,
        },
    }
}
fn request(nonce: u64, revision: u64, method: file::Method) -> file::Request {
    file::Request {
        request_id: nonce,
        operation_id: nonce,
        deadline: Deadline::new(CUT).unwrap(),
        expected_revision: revision,
        method,
    }
}
fn handle(gateway: &mut Gateway<'_, '_, Disk>, route: Binding, request: file::Request) -> Dispatch {
    gateway
        .handle(
            Captured {
                endpoint: route.endpoint,
                caller: route.caller,
                lease_epoch: route.lease_epoch,
                now: 1,
            },
            &request.encode().unwrap(),
            0,
            Loan::None,
        )
        .unwrap()
}

#[test]
fn legacy_and_dataset_keys_keep_namespaces_and_retirement_effects_separate() {
    let disk = Disk::default();
    let mut store_scratch = Box::new(StoreScratch::empty());
    let mut scratch = Box::new(Scratch::empty());
    let (dataset, object, _) = dataset(disk.clone(), &mut store_scratch);
    let mut gateway = Gateway::new(dataset, &mut scratch);
    let route = route(object);
    let key = Key::Dataset(gateway.bind(route).unwrap());
    let metadata = gateway.owner_metadata(object).unwrap();
    let before = disk.counts();
    old_key().revoke(&mut gateway).unwrap();
    assert_eq!(
        old_key().retire_quiescent(&mut gateway, true, CUT),
        Err(RetireError::StorageFenced)
    );
    old_key()
        .retire_quiescent(&mut gateway, false, CUT)
        .unwrap();
    assert_eq!(disk.counts(), before);
    assert_eq!(gateway.dataset_id(), [0x84; 16]);
    assert_ne!(gateway.dataset_id(), legacy::ORIGINAL_VOLUME);
    assert_eq!(gateway.owner_metadata(object).unwrap(), metadata);
    assert_eq!(
        key.retire_quiescent(&mut gateway, false, CUT),
        Err(RetireError::Active)
    );
    key.revoke(&mut gateway).unwrap();
    key.retire_quiescent(&mut gateway, false, CUT).unwrap();
    assert_eq!(disk.counts(), (before.0, before.1, before.2 + 1));
    assert_eq!(
        key.retire_quiescent(&mut gateway, false, CUT),
        Err(RetireError::Stale)
    );
    assert_eq!(gateway.owner_metadata(object).unwrap(), metadata);
}

#[test]
fn accepted_dataset_publication_cannot_be_cleared_by_legacy_reconcile() {
    let disk = Disk::default();
    let mut store_scratch = Box::new(StoreScratch::empty());
    let mut scratch = Box::new(Scratch::empty());
    let (dataset, object, revision) = dataset(disk.clone(), &mut store_scratch);
    let mut gateway = Gateway::new(dataset, &mut scratch);
    let route = route(object);
    let key = Key::Dataset(gateway.bind(route).unwrap());
    let begin = request(
        1,
        revision,
        file::Method::BeginWrite {
            length: 0,
            digest: crate::hash(&[]),
        },
    );
    let result = handle(&mut gateway, route, begin);
    let response = file::client_decode(begin, result.frame(), 0).unwrap();
    assert_eq!(response.outcome, Outcome::Completed);
    let commit = request(
        2,
        revision,
        file::Method::Commit {
            transfer_id: response.transfer_id,
            length: 0,
            digest: crate::hash(&[]),
        },
    );
    assert!(matches!(
        handle(&mut gateway, route, commit),
        Dispatch::Accepted { .. }
    ));
    key.revoke(&mut gateway).unwrap();
    old_key().revoke(&mut gateway).unwrap();
    let pending = gateway.pending();
    let before = disk.counts();
    assert_eq!(
        Key::check_quiescent(&gateway, false),
        Err(RetireError::Busy)
    );
    assert_eq!(
        old_key().retire_quiescent(&mut gateway, false, CUT),
        Err(RetireError::Busy)
    );
    assert_eq!(
        key.retire_quiescent(&mut gateway, false, CUT),
        Err(RetireError::Busy)
    );
    assert_eq!(gateway.pending(), pending);
    assert_eq!(disk.counts(), before);
    assert!(matches!(
        gateway.poll_commit(CUT).unwrap(),
        Dispatch::Retained { .. }
    ));
    assert_eq!(
        old_key().retire_quiescent(&mut gateway, false, CUT),
        Err(RetireError::Busy)
    );
    assert!(gateway.pending().is_some());
    assert_eq!(disk.counts(), before);
}

#[test]
fn uncertain_dataset_retirement_fences_legacy_switch_without_more_io() {
    let disk = Disk::default();
    let mut store_scratch = Box::new(StoreScratch::empty());
    let mut scratch = Box::new(Scratch::empty());
    let (dataset, object, _) = dataset(disk.clone(), &mut store_scratch);
    let mut gateway = Gateway::new(dataset, &mut scratch);
    let key = Key::Dataset(gateway.bind(route(object)).unwrap());
    key.revoke(&mut gateway).unwrap();
    disk.0.borrow_mut().fail_flush = true;
    assert_eq!(
        key.retire_quiescent(&mut gateway, false, CUT),
        Err(RetireError::Uncertain)
    );
    let before = disk.counts();
    assert_eq!(
        Key::check_quiescent(&gateway, false),
        Err(RetireError::StorageFenced)
    );
    assert_eq!(
        old_key().retire_quiescent(&mut gateway, false, CUT),
        Err(RetireError::StorageFenced)
    );
    assert_eq!(disk.counts(), before);
    assert!(gateway.into_storage().is_err());
}
