//! Include as a child of the actual client module only under a new explicit
//! negative-probe feature. Ordinary connect keeps its immutable NetworkPolicy.
use super::*;
impl<W: Window, T: Transport> Client<W, T> {
    /// A real canonical request through the same sole affine window/transport.
    /// Only exact Refused counts; uncertainty retains the ordinary owner fence.
    /// Call after actual lease readiness and all previous client work settles.
    pub fn probe_forbidden_destination(
        &mut self,
        destination: [u8; 6],
        now: u64,
        original_child_cut: u64,
    ) -> Result<(), Error> {
        if !self.initialized || self.shutdown_cut.is_some() {
            return Err(Error::State);
        }
        match self.request(Operation::Connect, &destination, now, original_child_cut) {
            Err(Error::Remote(Status::Refused)) => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(Error::Response),
        }
    }
}
