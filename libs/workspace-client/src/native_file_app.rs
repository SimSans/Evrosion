//! Public Internal selected-file app profile. The unsafe entry boundary requires
//! actual selected loader custody; parsed bytes never prove a physical mapping.
#![allow(unsafe_code)]
use crate::{
    FileClient,
    native::{NativeLink, SelfFacts, self_facts},
    selection::Selection,
};
use core::{
    marker::PhantomData,
    sync::atomic::{AtomicBool, Ordering},
};
use ev_userspace_contract::{Bootstrap, root_v5::resources};
use ev_userspace_runtime as rt;

pub const BASE: usize = 1 << 39;
pub const SURFACE_ADDRESS: usize = BASE + resources::APP_SURFACE_FIRST_PAGE as usize * 4096;
pub const FILE_ADDRESS: usize = BASE + resources::APP_FILE_FIRST_PAGE as usize * 4096;
pub const STARTUP_ADDRESS: usize = BASE + resources::STARTUP_PAGE as usize * 4096;
pub const LINKER_SCRIPT: &str = include_str!("../file-app.ld");
static CLAIMED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Startup,
    Roles,
    Identity,
    Handle,
    Claimed,
    Receive,
    Selection,
    Mapping,
}
pub struct Grant {
    pub selection: Selection,
    pub file: FileClient<NativeLink>,
}
/// One fixed mapping owner, permanently claimed for this process lifetime.
/// This deliberately supports one selection. Drop does not return an accepted
/// loan, and no safe reconstruction or release shortcut permits window reuse.
pub struct FileApp {
    facts: SelfFacts,
    pub present: u64,
    pub events: u64,
    pub control: u64,
    inbox: u64,
    received: bool,
    data_peer: Option<crate::app_data::Peer>,
    _one_thread: PhantomData<*mut ()>,
}
/// Syntax/selected-role validation only; no mapping or capability proof.
pub fn validate_startup(bytes: &[u8]) -> Result<[u64; 6], Error> {
    let parsed = Bootstrap::parse(bytes).map_err(|_| Error::Startup)?;
    if parsed.grants().count() != 6 || bytes.len() != ev_userspace_contract::SIZE {
        return Err(Error::Roles);
    }
    let limits = core::array::from_fn(|i| {
        u64::from_le_bytes(bytes[40 + i * 8..48 + i * 8].try_into().unwrap())
    });
    if limits != resources::JOB_TEMPLATE_LIMITS[3] {
        return Err(Error::Roles);
    }
    let shapes = [(1, 7), (2, 8), (2, 8), (2, 272), (1, 7), (2, 272)];
    let mut handles = [0; 6];
    for (index, grant) in parsed.grants().enumerate() {
        if grant.selector != index as u64 + 1 || (grant.kind, grant.rights) != shapes[index] {
            return Err(Error::Roles);
        }
        handles[index] = grant.handle;
    }
    Ok(handles)
}
impl FileApp {
    pub const fn facts(&self) -> SelfFacts {
        self.facts
    }
    /// Move out the original immutable Root transport peer once. This grants
    /// no AppPrivateData namespace or permission; actual Root admission and
    /// verified AppId/manifest policy must establish those independently.
    pub fn take_app_data_peer(&mut self) -> Option<crate::app_data::Peer> {
        self.data_peer.take()
    }
    /// # Safety
    /// The entry must be the actual measured selected six-role application,
    /// with the initialized immutable startup page and sole-writer surface and
    /// two-page FileWindow mapped at this public profile's addresses. No other
    /// thread/adapter may access those windows or reconstruct their client.
    pub unsafe fn from_entry(record: usize, length: usize) -> Result<Self, Error> {
        if record != STARTUP_ADDRESS || length != ev_userspace_contract::SIZE {
            return Err(Error::Startup);
        }
        // SAFETY: caller establishes the actual immutable startup mapping;
        // exact public profile address and extent were checked above.
        let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length) };
        let handles = validate_startup(bytes)?;
        let parsed = Bootstrap::parse(bytes).map_err(|_| Error::Startup)?;
        let facts = self_facts().map_err(|_| Error::Identity)?;
        if facts.process != parsed.process() || facts.registered_incarnation != parsed.incarnation()
        {
            return Err(Error::Identity);
        }
        for (handle, rights) in handles.into_iter().zip([7, 8, 8, 272, 7, 272]) {
            let reply = rt::inspect(handle, rights);
            if reply.status != 0 || reply.value != 0 || reply.capability != 0 {
                return Err(Error::Handle);
            }
        }
        CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Claimed)?;
        Ok(Self {
            facts,
            present: handles[1],
            events: handles[2],
            control: handles[3],
            inbox: handles[5],
            received: false,
            data_peer: Some(crate::app_data::Peer::admitted(
                facts, handles[2], handles[3],
            )),
            _one_thread: PhantomData,
        })
    }
    pub fn receive_selection(&mut self) -> Result<Option<Grant>, Error> {
        if self.received {
            return Ok(None);
        }
        let reply = rt::receive(self.inbox);
        if reply.status == 2 && reply.value == 0 && reply.capability == 0 {
            return Ok(None);
        }
        self.received = true;
        if reply.status != 0 || reply.capability == 0 {
            return Err(Error::Receive);
        }
        let bytes = core::array::from_fn::<_, 256, _>(|i| {
            // SAFETY: this permanently claimed owner has never constructed a
            // previous client or accepted a request on its admitted FileWindow.
            unsafe { ((FILE_ADDRESS + i) as *const u8).read_volatile() }
        });
        let selection = Selection::decode(&bytes).ok().filter(|s| {
            s.matches_receiver(
                reply.value,
                self.facts.process,
                self.facts.thread,
                self.facts.registered_incarnation,
            )
        });
        let inspected = rt::inspect(reply.capability, 8);
        let Some(selection) = selection
            .filter(|_| inspected.status == 0 && inspected.value == 0 && inspected.capability == 0)
        else {
            let _ = rt::call(rt::syscall::CLOSE, reply.capability, 0, 0);
            return Err(Error::Selection);
        };
        // SAFETY: the one-way process claim, receive gate and actual entry
        // precondition establish sole mapping ownership with no previous loan.
        let link =
            unsafe { NativeLink::from_admitted_mapping(FILE_ADDRESS, 8192, reply.capability) };
        let link = match link {
            Ok(link) => link,
            Err(_) => {
                let _ = rt::call(rt::syscall::CLOSE, reply.capability, 0, 0);
                return Err(Error::Mapping);
            }
        };
        Ok(Some(Grant {
            selection,
            file: FileClient::new(link),
        }))
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;
    use crate::app_data::{Client, Error, SendResult, Sender};
    use ev_userspace_contract::app_data as wire;

    #[test]
    fn original_root_peer_is_immutable_and_can_only_be_taken_once() {
        // Synthetic handles exercise only the safe protocol model. No actual
        // mapping, Kernel grant, Root admission or private namespace is claimed.
        let facts = SelfFacts {
            process: 7,
            thread: 9,
            registered_incarnation: 0,
        };
        let mut app = FileApp {
            facts,
            present: 2,
            events: 3,
            control: 4,
            inbox: 6,
            received: false,
            data_peer: Some(crate::app_data::Peer::admitted(facts, 3, 4)),
            _one_thread: PhantomData,
        };
        app.events = 30;
        app.control = 40;
        let peer = app.take_app_data_peer().unwrap();
        assert!(app.take_app_data_peer().is_none());
        struct Model;
        impl Sender for Model {
            fn try_send(&mut self, events: u64, bytes: [u8; 8], deadline: u64) -> SendResult {
                assert_eq!(
                    (events, bytes, deadline),
                    (3, wire::Request::Read.encode(), 100)
                );
                SendResult::Accepted
            }
        }
        let mut client = Client::claim(peer, 0, 100).unwrap();
        client.begin_read(1).unwrap();
        client.try_send(2, &mut Model).unwrap();
        let response = wire::Response::Value(42).encode();
        assert_eq!(
            client.observe_root_control(40, &response, 0, 3),
            Err(Error::Peer)
        );
        client.observe_root_control(4, &response, 0, 4).unwrap();
        assert_eq!(client.finish(), Ok(42));
    }
}
