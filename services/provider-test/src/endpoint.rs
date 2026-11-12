//! Additive userspace adapter for an already installed endpoint handle. Parsing
//! an integer or calling new() is NOT an authority grant; actual RPC22 resolves
//! the caller's live handle table and SEND permission at every invocation.
use core::num::NonZeroU64;
use ev_userspace_contract::provider::Transport;
pub struct Endpoint {
    capability: NonZeroU64,
}
impl Endpoint {
    pub fn new(installed_handle: u64) -> Option<Self> {
        if installed_handle == u64::MAX {
            return None;
        }
        NonZeroU64::new(installed_handle).map(|capability| Self { capability })
    }
}
impl Transport for Endpoint {
    type Error = ev_userspace_runtime::rpc::Error;
    fn call(
        &mut self,
        request: [u8; 8],
        absolute_deadline: u64,
    ) -> Result<([u8; 8], usize), Self::Error> {
        // Safe SDK rejects nonzero capability outputs and retries only canonical
        // preaccept Busy with the same request/deadline under finite bounds.
        ev_userspace_runtime::rpc::call(self.capability.get(), request, absolute_deadline)
            .map(|reply| (reply, 0))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn syntactic_endpoint_wrapper_never_certifies_live_authority() {
        assert!(Endpoint::new(0).is_none());
        assert!(Endpoint::new(u64::MAX).is_none());
        // Nonzero diagnostics do not certify a handle. Actual permission is
        // deliberately untested until the real source-built Runtime fixture.
        assert!(Endpoint::new(1).is_some());
    }
}
