//! The App owns a writable page, not merely the protocol's first256 bytes.
//! Its padding is untrusted input; rejecting it must not terminate File or
//! begin a Store operation. The actual adapter supplies bounded volatile reads.
use ev_file::{ErrorCode, Response};

/// Check the entire App-controlled padding before loading or interpreting the
/// body. The callback runs only after admission and returns the ordinary File
/// response. This check grants no shared-memory lease or caller authority.
pub fn handle(mut read: impl FnMut(usize) -> u8, admitted: impl FnOnce() -> Response) -> Response {
    for index in ev_userspace_contract::file::FRAME_BYTES..4096 {
        if read(index) != 0 {
            return Response::Error {
                code: ErrorCode::Malformed,
            };
        }
    }
    admitted()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use ev_file::{Bindings, Envelope, Gateway, Payload, Request};
    use ev_store::{BootPolicy, GenerationId, GenerationManifest, Sector, SectorIo, Store};
    use std::{cell::RefCell, rc::Rc, vec, vec::Vec};

    #[test]
    fn every_app_controlled_padding_byte_refuses_before_the_body_or_store_callback() {
        let mut page = [0u8; 4096];
        for index in 256..4096 {
            page[index] = 1;
            let response = handle(
                |offset| page[offset],
                || panic!("malformed App padding reached File body or Store"),
            );
            assert_eq!(
                Response::decode(&response.encode()),
                Ok(Response::Error {
                    code: ErrorCode::Malformed
                })
            );
            assert_eq!(page[index], 1); // No fabricated repair of client bytes.
            page[index] = 0;
        }
    }

    struct Disk {
        bytes: Vec<Sector>,
        reads: u64,
        writes: u64,
        flushes: u64,
    }
    struct Device(Rc<RefCell<Disk>>);
    impl SectorIo for Device {
        type Error = ();
        fn sectors(&self) -> u64 {
            14
        }
        fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> Result<(), ()> {
            let mut disk = self.0.borrow_mut();
            *out = *disk.bytes.get(lba as usize).ok_or(())?;
            disk.reads += 1;
            Ok(())
        }
        fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> Result<(), ()> {
            let mut disk = self.0.borrow_mut();
            *disk.bytes.get_mut(lba as usize).ok_or(())? = *bytes;
            disk.writes += 1;
            Ok(())
        }
        fn flush(&mut self, _: u64) -> Result<(), ()> {
            self.0.borrow_mut().flushes += 1;
            Ok(())
        }
    }
    #[test]
    fn malformed_page_cannot_mutate_real_store_and_a_later_valid_request_still_works() {
        const DEADLINE: u64 = 100_000;
        let disk = Rc::new(RefCell::new(Disk {
            bytes: vec![[0; 512]; 14],
            reads: 0,
            writes: 0,
            flushes: 0,
        }));
        let mut envelope = [0; 256];
        let length = Envelope::initial(b"original")
            .unwrap()
            .encode(&mut envelope);
        let store = Store::format_new(
            Device(disk.clone()),
            GenerationManifest {
                generation: GenerationId::new(1).unwrap(),
                cohort: [1; 32],
                supervisor_image: [2; 32],
                abi: [3; 32],
                health_contract: [4; 32],
                health_version: 1,
                required_checks: 3,
            },
            &envelope[..length],
            BootPolicy::new(3).unwrap(),
            DEADLINE,
        )
        .unwrap_or_else(|e| panic!("real Store format failed: {:?}", e.error));
        let mut gateway = Gateway::new(store, Bindings::new(10, 11).unwrap());
        let mut page = [0u8; 4096];
        page[..256].copy_from_slice(
            &Request::Replace {
                counter: 1,
                payload: Payload::new(b"replacement").unwrap(),
            }
            .encode(),
        );
        let before = {
            let d = disk.borrow();
            (d.bytes.clone(), d.reads, d.writes, d.flushes)
        };
        for index in [256, 511, 512, 4095] {
            page[index] = 0x80;
            let response = handle(
                |offset| page[offset],
                || gateway.handle_frame(11, &page[..256], DEADLINE).unwrap(),
            );
            assert_eq!(
                response,
                Response::Error {
                    code: ErrorCode::Malformed
                }
            );
            let d = disk.borrow();
            assert_eq!(
                (&d.bytes, d.reads, d.writes, d.flushes),
                (&before.0, before.1, before.2, before.3)
            );
            page[index] = 0;
        }
        assert_eq!(
            handle(
                |offset| page[offset],
                || gateway.handle_frame(11, &page[..256], DEADLINE).unwrap()
            ),
            Response::Replaced {
                counter: 1,
                replayed: false
            }
        );
        let Response::Read { counter, payload } =
            gateway.handle(10, Request::Read, DEADLINE).unwrap()
        else {
            panic!("actual File read did not return content");
        };
        assert_eq!(
            (counter, payload.as_slice()),
            (1, b"replacement".as_slice())
        );
    }
}
