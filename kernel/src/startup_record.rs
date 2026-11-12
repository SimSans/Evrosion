//! Typed startup bytes; only a matching measured load plan may select them.
use crate::executable::StartupLayout;
use ev_userspace_contract::root_v2;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Record,
    Layout,
}
#[derive(Clone, Copy)]
enum Bytes<'a> {
    V1(&'a [u8; ev_userspace_contract::SIZE]),
    RootV2(&'a [u8; root_v2::SIZE]),
    NativeRoot(&'a [u8; root_v2::native::SIZE]),
}
/// Private discriminant prevents a raw slice from claiming a format or size.
#[derive(Clone, Copy)]
pub struct Record<'a> {
    bytes: Bytes<'a>,
}
impl<'a> Record<'a> {
    pub fn service_v1(bytes: &'a [u8; ev_userspace_contract::SIZE]) -> Result<Self, Error> {
        ev_userspace_contract::Bootstrap::parse(bytes).map_err(|_| Error::Record)?;
        Ok(Self {
            bytes: Bytes::V1(bytes),
        })
    }
    pub fn root_v2(bytes: &'a [u8; root_v2::SIZE]) -> Result<Self, Error> {
        root_v2::FullGraph::parse(bytes).map_err(|_| Error::Record)?;
        Ok(Self {
            bytes: Bytes::RootV2(bytes),
        })
    }
    /// Profile3 is explicitly parsed rather than admitted by spare RootV2
    /// capacity. The shared layout is physical size, not interchangeable ABI.
    pub fn native_root(bytes: &'a [u8; root_v2::native::SIZE]) -> Result<Self, Error> {
        root_v2::native::FullGraph::parse(bytes).map_err(|_| Error::Record)?;
        Ok(Self {
            bytes: Bytes::NativeRoot(bytes),
        })
    }
    pub fn bytes(self) -> &'a [u8] {
        match self.bytes {
            Bytes::V1(b) => b,
            Bytes::RootV2(b) => b,
            Bytes::NativeRoot(b) => b,
        }
    }
    pub fn layout(self) -> StartupLayout {
        match self.bytes {
            Bytes::V1(_) => StartupLayout::ServiceV1,
            Bytes::RootV2(_) | Bytes::NativeRoot(_) => StartupLayout::RootV2,
        }
    }
    pub fn check_layout(self, expected: StartupLayout) -> Result<(), Error> {
        if self.layout() != expected {
            return Err(Error::Layout);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::{Context, Grant};
    fn c() -> Context {
        Context {
            epoch: 1,
            incarnation: 2,
            process: 3,
            limits: [4096, 256, 7, 7],
            manifest: [4; 32],
            authority: [5; 32],
        }
    }
    #[test]
    fn root_v2_loader_discriminant_cannot_cross_service_abi() {
        let a = ev_userspace_contract::encode(
            c(),
            &[Grant {
                selector: 1,
                handle: 10,
                kind: 1,
                rights: 1,
            }],
        )
        .unwrap();
        let a = Record::service_v1(&a).unwrap();
        let b = root_v2::encode_full_graph(c(), core::array::from_fn(|i| i as u64 + 10)).unwrap();
        let b = Record::root_v2(&b).unwrap();
        assert_eq!(a.bytes().len(), 336);
        assert_eq!(b.bytes().len(), 720);
        assert!(a.check_layout(StartupLayout::RootV2).is_err());
        assert!(b.check_layout(StartupLayout::ServiceV1).is_err());
        assert!(b.check_layout(StartupLayout::None).is_err());
    }
    #[test]
    fn root_v2_actual_plan_reserves_one_ro_page_without_relaxing_v1_limits() {
        use crate::root_producer_v2::{Description, Identity, encode_current};
        const IMAGE: &[u8] = include_bytes!("../fixtures/bootstrap-static-v1.elf");
        let d = Description::full_graph(
            [4096, 256, 7, 7],
            3,
            60,
            core::array::from_fn(|i| Identity {
                object: i as u64,
                lineage: i as u64,
            }),
        )
        .unwrap()
        .bind_catalogue([7; 32]);
        let e = encode_current(IMAGE, &d).unwrap();
        let m = crate::root_manifest_v2::verify(e.bytes(), e.digest(), IMAGE)
            .unwrap()
            .current_profile()
            .unwrap();
        let plan = crate::executable::Image::from_root_manifest_v2(&m).unwrap();
        assert_eq!(plan.startup_layout(), StartupLayout::RootV2);
        assert_eq!(plan.startup_layout().bytes(), Some(720));
        assert_eq!(plan.bootstrap_page(), Some(plan.base() + 509 * 4096));
        assert_eq!(plan.required_frames(), plan.pages().count() as u64 + 6);
        assert_eq!(ev_userspace_contract::MAX_GRANTS, 8);
    }
}
