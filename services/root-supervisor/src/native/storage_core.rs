//! Safe protocol ownership core. One Backend owns a Window and transport; region
//! devices exclusively reborrow it. Write permission is owner policy, not a cap.
#![forbid(unsafe_code)]
use ev_block_service::store_io::{Window, Wire};
use ev_store::{Sector, SectorIo, native::Region};
use ev_userspace_contract::block::{Request, Response};
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
    wire: T,
    window: W,
    stop: u64,
    poisoned: bool,
    mutations: u64,
}
impl<T: Wire, W: Window> Backend<T, W> {
    pub fn new(wire: T, window: W, stop: u64) -> Option<Self> {
        stop.checked_add(1024).filter(|_| stop != 0)?;
        Some(Self {
            wire,
            window,
            stop,
            poisoned: false,
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
    pub fn mutations(&self) -> u64 {
        self.mutations
    }
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
    fn preflight(&self, deadline: u64) -> Result<(), Error<T::Error>> {
        if self.poisoned {
            Err(Error::Recovery)
        } else if deadline <= self.stop || deadline > self.stop + 1024 {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
    fn request(&mut self, request: Request, deadline: u64) -> Result<(), Error<T::Error>> {
        self.preflight(deadline)?;
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
        Ok(())
    }
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
        self.backend.preflight(deadline)?;
        let sector = self.sector(lba)?;
        self.backend.request(Request::Read { sector }, deadline)?;
        self.backend.window.load(out);
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &Sector, deadline: u64) -> Result<(), Self::Error> {
        self.backend.preflight(deadline)?;
        let sector = self.sector(lba)?;
        if !self.writes {
            return Err(Error::NoConsent);
        }
        self.backend.window.store(bytes);
        self.backend.request(Request::Write { sector }, deadline)
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Self::Error> {
        self.backend.preflight(deadline)?;
        if !self.writes {
            return Err(Error::NoConsent);
        }
        self.backend.request(Request::Flush, deadline)
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
}
