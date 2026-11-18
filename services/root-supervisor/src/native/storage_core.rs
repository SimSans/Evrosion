//! Safe protocol ownership core. One Backend owns a Window and transport; region
//! devices exclusively reborrow it. Write permission is owner policy, not a cap.
#![forbid(unsafe_code)]
use ev_block_service::store_io::{Window, Wire};
use ev_store::{Sector, SectorIo, native::Region};
use ev_userspace_contract::block::{Request, Response};
#[cfg(feature = "native-network")]
#[path = "backend_slot.rs"]
mod backend_slot;
#[cfg(feature = "native-network")]
#[path = "content_adapter.rs"]
pub mod content;
#[cfg(feature = "native-network")]
pub(crate) use backend_slot::BackendSlot;
#[cfg(not(feature = "native-network"))]
pub(crate) type BackendSlot<T, W> = Backend<T, W>;
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Bounds,
    Deadline,
    NoConsent,
    Recovery,
    Transport(E),
    Decode,
    Reply,
    Counter,
}
pub struct Backend<T, W> {
    #[cfg(feature = "native-network")]
    identity: u64,
    wire: T,
    window: W,
    stop: u64,
    poisoned: bool,
    #[cfg(feature = "native-network")]
    in_flight: bool,
    mutations: u64,
}
impl<T: Wire, W: Window> Backend<T, W> {
    pub fn new(wire: T, window: W, stop: u64) -> Option<Self> {
        stop.checked_add(1024)
            .filter(|_| stop != 0 || wire.supports_session())?;
        Some(Self {
            #[cfg(feature = "native-network")]
            identity: next_identity()?,
            wire,
            window,
            stop,
            poisoned: false,
            #[cfg(feature = "native-network")]
            in_flight: false,
            mutations: 0,
        })
    }
    pub fn device(&mut self, region: Region, writes: bool) -> Device<'_, T, W> {
        Device {
            backend: self,
            region,
            writes,
        }
    }
    #[cfg(feature = "native-network")]
    pub fn network_device(
        &mut self,
        area: ev_store::network::Area,
        writes: bool,
    ) -> NetworkDevice<'_, T, W> {
        NetworkDevice {
            backend: self,
            area,
            writes,
        }
    }
    pub fn mutations(&self) -> u64 {
        self.mutations
    }
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
    #[cfg(feature = "native-network")]
    pub fn has_unresolved_io(&self) -> bool {
        self.poisoned || self.in_flight
    }
    #[cfg(not(feature = "native-network"))]
    pub(crate) fn busy(&self) -> bool {
        false
    }
    fn preflight(&self, deadline: u64) -> Result<u64, Error<T::Error>> {
        if self.poisoned {
            return Err(Error::Recovery);
        }
        let child = if self.stop == 0 {
            self.wire
                .capture_session_deadline(deadline)
                .ok_or(Error::Deadline)?
        } else {
            deadline
        };
        if (self.stop != 0 && (deadline <= self.stop || deadline > self.stop + 1024))
            || deadline == 0
            || deadline == u64::MAX
            || child == 0
            || child == u64::MAX
            || child > deadline
        {
            Err(Error::Deadline)
        } else {
            Ok(child)
        }
    }
    fn request(&mut self, request: Request, deadline: u64) -> Result<(), Error<T::Error>> {
        // The sole mutable window/transport loan remains unsettled until the
        // exact cap-free scoped reply and checked accounting finish. No Root
        // lifecycle/event pump runs inside this synchronous borrowed device.
        #[cfg(feature = "native-network")]
        {
            self.in_flight = true;
        }
        let reply = self.wire.call(request.encode(), deadline).map_err(|e| {
            self.poisoned = true;
            Error::Transport(e)
        })?;
        let response = Response::decode(&reply).map_err(|_| {
            self.poisoned = true;
            Error::Decode
        })?;
        if response != request.success() {
            self.poisoned = true;
            return Err(Error::Reply);
        }
        if matches!(request, Request::Write { .. } | Request::Flush) {
            self.mutations = self.mutations.checked_add(1).ok_or_else(|| {
                self.poisoned = true;
                Error::Counter
            })?;
        }
        #[cfg(feature = "native-network")]
        {
            self.in_flight = false;
        }
        Ok(())
    }
}
#[cfg(feature = "native-network")]
fn next_identity() -> Option<u64> {
    use core::sync::atomic::{AtomicU64, Ordering};
    // Private in-process ownership identity, never persisted or wire authority.
    // Exhaustion refuses a new Backend; it never wraps/reuses a live identity.
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_add(1)
    })
    .ok()
}
pub struct Device<'a, T, W> {
    backend: &'a mut Backend<T, W>,
    region: Region,
    writes: bool,
}
impl<T: Wire, W: Window> Device<'_, T, W> {
    fn sector(&self, local: u64) -> Result<u32, Error<T::Error>> {
        self.region.wire_sector(local).ok_or(Error::Bounds)
    }
}
impl<T: Wire, W: Window> SectorIo for Device<'_, T, W> {
    type Error = Error<T::Error>;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Self::Error> {
        let child = self.backend.preflight(deadline)?;
        let sector = self.sector(lba)?;
        self.backend.request(Request::Read { sector }, child)?;
        self.backend.window.load(out);
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &Sector, deadline: u64) -> Result<(), Self::Error> {
        let child = self.backend.preflight(deadline)?;
        let sector = self.sector(lba)?;
        if !self.writes {
            return Err(Error::NoConsent);
        }
        self.backend.window.store(bytes);
        self.backend.request(Request::Write { sector }, child)
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Self::Error> {
        let child = self.backend.preflight(deadline)?;
        if !self.writes {
            return Err(Error::NoConsent);
        }
        self.backend.request(Request::Flush, child)
    }
}
/// Additive device view over the same actual Backend/window. The network
/// profile is a compiled Root choice; every operation still uses its captured
/// session cut, canonical reply validation and global uncertain-I/O fence.
#[cfg(feature = "native-network")]
pub struct NetworkDevice<'a, T, W> {
    backend: &'a mut Backend<T, W>,
    area: ev_store::network::Area,
    writes: bool,
}
#[cfg(feature = "native-network")]
impl<T: Wire, W: Window> NetworkDevice<'_, T, W> {
    fn preflight(&self, deadline: u64) -> Result<u64, Error<T::Error>> {
        if self.backend.stop != 0 || !self.backend.wire.supports_session() {
            return Err(Error::NoConsent);
        }
        self.backend.preflight(deadline)
    }
    fn sector(&self, local: u64) -> Result<u32, Error<T::Error>> {
        self.area.wire_sector(local).ok_or(Error::Bounds)
    }
}
#[cfg(feature = "native-network")]
impl<T: Wire, W: Window> SectorIo for NetworkDevice<'_, T, W> {
    type Error = Error<T::Error>;
    fn sectors(&self) -> u64 {
        self.area.sectors()
    }
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Self::Error> {
        let child = self.preflight(deadline)?;
        let sector = self.sector(lba)?;
        self.backend.request(Request::Read { sector }, child)?;
        self.backend.window.load(out);
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &Sector, deadline: u64) -> Result<(), Self::Error> {
        let child = self.preflight(deadline)?;
        let sector = self.sector(lba)?;
        if !self.writes {
            return Err(Error::NoConsent);
        }
        self.backend.window.store(bytes);
        self.backend.request(Request::Write { sector }, child)
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Self::Error> {
        let child = self.preflight(deadline)?;
        if !self.writes {
            return Err(Error::NoConsent);
        }
        self.backend.request(Request::Flush, child)
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
        vec::Vec,
    };
    #[derive(Clone)]
    struct Buffer {
        bytes: Rc<RefCell<Sector>>,
        writes: Rc<Cell<usize>>,
    }
    impl Window for Buffer {
        fn load(&self, out: &mut Sector) {
            *out = *self.bytes.borrow();
        }
        fn store(&self, b: &Sector) {
            *self.bytes.borrow_mut() = *b;
            self.writes.set(self.writes.get() + 1);
        }
    }
    struct Link {
        requests: Rc<RefCell<Vec<Request>>>,
        fail: bool,
    }
    impl Wire for Link {
        type Error = ();
        fn call(&mut self, bytes: [u8; 8], _: u64) -> Result<[u8; 8], ()> {
            let r = Request::decode(&bytes).unwrap();
            self.requests.borrow_mut().push(r);
            if self.fail {
                Err(())
            } else {
                Ok(r.success().encode())
            }
        }
    }
    fn fixture(fail: bool) -> (Backend<Link, Buffer>, Rc<RefCell<Vec<Request>>>, Buffer) {
        let buffer = Buffer {
            bytes: Rc::new(RefCell::new([7; 512])),
            writes: Rc::new(Cell::new(0)),
        };
        let log = Rc::new(RefCell::new(Vec::new()));
        (
            Backend::new(
                Link {
                    requests: log.clone(),
                    fail,
                },
                buffer.clone(),
                100,
            )
            .unwrap(),
            log,
            buffer,
        )
    }
    #[test]
    fn preflight_denials_do_not_publish_window_or_request() {
        let (mut b, log, buffer) = fixture(false);
        let mut d = b.device(Region::AppRegistry, false);
        assert_eq!(d.write(0, &[1; 512], 200), Err(Error::NoConsent));
        assert_eq!(d.flush(200), Err(Error::NoConsent));
        assert_eq!(d.read(14, &mut [0; 512], 200), Err(Error::Bounds));
        assert_eq!(d.read(0, &mut [0; 512], 100), Err(Error::Deadline));
        assert!(log.borrow().is_empty());
        assert_eq!(buffer.writes.get(), 0);
    }
    #[test]
    fn actual_typed_completion_counts_and_regions_serialize() {
        let (mut b, log, _) = fixture(false);
        b.device(Region::AppRegistry, true)
            .write(0, &[2; 512], 200)
            .unwrap();
        b.device(Region::AppRegistry, true).flush(200).unwrap();
        b.device(Region::AppData, false)
            .read(13, &mut [0; 512], 200)
            .unwrap();
        assert_eq!(
            *log.borrow(),
            [
                Request::Write { sector: 16 },
                Request::Flush,
                Request::Read { sector: 45 }
            ]
        );
        assert_eq!(b.mutations(), 2);
    }
    #[test]
    fn uncertain_transport_latches_before_any_retry_or_new_window_write() {
        let (mut b, log, buffer) = fixture(true);
        assert_eq!(
            b.device(Region::AppData, true).write(1, &[2; 512], 200),
            Err(Error::Transport(()))
        );
        assert!(b.poisoned());
        assert_eq!(b.mutations(), 0);
        assert_eq!(
            b.device(Region::AppRegistry, true).write(1, &[3; 512], 200),
            Err(Error::Recovery)
        );
        assert_eq!(log.borrow().len(), 1);
        assert_eq!(buffer.writes.get(), 1);
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CaptureEvent {
        Capture(u64, u64),
        Store,
        Call(u64),
        Load,
    }
    struct CaptureLink {
        events: Rc<RefCell<Vec<CaptureEvent>>>,
        captures: Cell<usize>,
    }
    impl Wire for CaptureLink {
        type Error = ();
        fn supports_session(&self) -> bool {
            true
        }
        fn capture_session_deadline(&self, original: u64) -> Option<u64> {
            let index = self.captures.get();
            self.captures.set(index + 1);
            let child = [6000, 6500, 7000, 8001][index];
            self.events
                .borrow_mut()
                .push(CaptureEvent::Capture(original, child));
            Some(child)
        }
        fn call(&mut self, bytes: [u8; 8], child: u64) -> Result<[u8; 8], ()> {
            self.events.borrow_mut().push(CaptureEvent::Call(child));
            Ok(Request::decode(&bytes).unwrap().success().encode())
        }
    }
    struct CaptureWindow(Rc<RefCell<Vec<CaptureEvent>>>);
    impl Window for CaptureWindow {
        fn store(&self, _: &Sector) {
            self.0.borrow_mut().push(CaptureEvent::Store);
        }
        fn load(&self, out: &mut Sector) {
            self.0.borrow_mut().push(CaptureEvent::Load);
            out.fill(7);
        }
    }
    #[test]
    fn native_transaction_captures_once_before_publication_and_never_recaptures_in_request() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut backend = Backend::new(
            CaptureLink {
                events: events.clone(),
                captures: Cell::new(0),
            },
            CaptureWindow(events.clone()),
            0,
        )
        .unwrap();
        backend
            .device(Region::AppData, true)
            .write(0, &[1; 512], 8000)
            .unwrap();
        backend
            .device(Region::AppRegistry, false)
            .read(0, &mut [0; 512], 8000)
            .unwrap();
        backend.device(Region::AppData, true).flush(8000).unwrap();
        assert_eq!(
            *events.borrow(),
            [
                CaptureEvent::Capture(8000, 6000),
                CaptureEvent::Store,
                CaptureEvent::Call(6000),
                CaptureEvent::Capture(8000, 6500),
                CaptureEvent::Call(6500),
                CaptureEvent::Load,
                CaptureEvent::Capture(8000, 7000),
                CaptureEvent::Call(7000),
            ]
        );
        assert_eq!(
            backend
                .device(Region::AppData, true)
                .write(0, &[2; 512], 8000),
            Err(Error::Deadline)
        );
        assert_eq!(
            events.borrow().last(),
            Some(&CaptureEvent::Capture(8000, 8001))
        );
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|event| matches!(event, CaptureEvent::Store))
                .count(),
            1
        );
        assert_eq!(backend.mutations(), 2);
    }
}
