//! Internal File2 client over one held exact-object route and retained window.
//! No wire identifier, path or requested right mints authority. The native link
//! uses actual scalar RPC and volatile copies; constructing it requires an
//! independently admitted mapping. Model links establish no guest acceptance.
#![no_std]
#![deny(unsafe_code)]

pub mod app_data;
pub mod namespace;
pub mod native;
pub mod native_file_app;
pub mod selection;
pub mod semantic;
pub mod transfer;
pub mod ui;

use ev_userspace_contract::{
    file_v2::{self as wire, Method, Pending, Request, Response},
    workspace::{Deadline, Error as CodecError, Outcome},
};
use sha2::{Digest, Sha256};

pub const WINDOW_BYTES: usize = 8192;
pub const BULK_OFFSET: usize = 4096;
pub const CHUNK_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    Clock,
    Rpc,
    Correlation,
    Mapping,
}
/// A link owns the actual mapped window and endpoint. exchange must retain the
/// immutable request/bulk through the RPC and return only its exact scalar
/// receipt. read_bulk is called only after exact response validation. It cannot
/// turn a deadline or formatter output into a loan-return proof. Native adapters
/// must grant a successful RPC reply only after the server finishes its access.
pub trait Link {
    fn now(&mut self) -> Result<u64, TransportError>;
    fn exchange(
        &mut self,
        request_id: u64,
        control: &[u8; wire::FRAME_BYTES],
        bulk: &[u8],
        deadline: Deadline,
    ) -> Result<[u8; wire::FRAME_BYTES], TransportError>;
    fn read_bulk(&mut self, out: &mut [u8]) -> Result<(), TransportError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Closed,
    Fenced,
    Exhausted,
    Deadline,
    Clock,
    Bounds,
    Digest,
    Codec(CodecError),
    Transport(TransportError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub request: Request,
    pub response: Response,
}
pub struct FileClient<L> {
    link: L,
    next_request: u64,
    next_operation: u64,
    last_clock: Option<u64>,
    retained: Option<Pending>,
    closed: bool,
}
impl FileClient<native::NativeLink> {
    /// Close only this actual local SEND handle after all control loans settled.
    /// This neither aborts durable staging nor releases Root's binding/physical
    /// mapping owners; those still need independent supervisor reconciliation.
    pub fn close_quiescent(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.fenced() {
            return Err(Error::Fenced);
        }
        // Even an unexpected close ABI failure must not permit more traffic.
        // The value/mapping remain owned for supervisor reconciliation.
        self.closed = true;
        self.link.close_quiescent().map_err(Error::Transport)
    }
}
impl<L: Link> FileClient<L> {
    /// A new incarnation starts its own nonces. Different real callers/routes
    /// remain separate in the server's authenticated binding table. Recreating
    /// a client on the SAME live route must retain its counters and quarantine;
    /// a native adapter must never use reconstruction as an uncertainty escape.
    pub fn new(link: L) -> Self {
        Self {
            link,
            next_request: 1,
            next_operation: 1,
            last_clock: None,
            retained: None,
            closed: false,
        }
    }
    pub fn retained_request(&self) -> Option<Request> {
        self.retained.as_ref().map(Pending::request)
    }
    pub const fn fenced(&self) -> bool {
        self.retained.is_some()
    }
    pub fn next_mutation_nonce(&self) -> Result<u64, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.fenced() {
            return Err(Error::Fenced);
        }
        if self.next_operation == u64::MAX || self.next_request == u64::MAX {
            return Err(Error::Exhausted);
        }
        Ok(self.next_operation)
    }
    /// issue allocates a distinct per-route mutation nonce. A full Save uses
    /// different operation nonces for Begin, each Chunk, Commit and Abort; the
    /// transfer ID returned by Begin remains independent. Query of an uncertain
    /// operation needs separately retained control/Root recovery, not this busy
    /// window. No new IDs or retry follow an accepted/uncertain completion.
    pub fn issue(
        &mut self,
        expected_revision: u64,
        method: Method,
        deadline: Deadline,
        bulk: &[u8],
        read_out: &mut [u8],
    ) -> Result<Completion, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.fenced() {
            return Err(Error::Fenced);
        }
        if matches!(method, Method::QueryOperation) {
            return Err(Error::Bounds);
        }
        if self.next_request == u64::MAX || self.next_operation == u64::MAX {
            return Err(Error::Exhausted);
        }
        match method {
            Method::WriteChunk { length, digest, .. } => {
                if bulk.len() != length as usize || !read_out.is_empty() {
                    return Err(Error::Bounds);
                }
                if <[u8; 32]>::from(Sha256::digest(bulk)) != digest {
                    return Err(Error::Digest);
                }
            }
            Method::Read { length, .. } => {
                if !bulk.is_empty() || read_out.len() < length as usize {
                    return Err(Error::Bounds);
                }
            }
            _ if !bulk.is_empty() || !read_out.is_empty() => return Err(Error::Bounds),
            _ => (),
        }
        let request = Request {
            request_id: self.next_request,
            operation_id: if matches!(method, Method::Read { .. }) {
                0
            } else {
                self.next_operation
            },
            deadline,
            expected_revision,
            method,
        };
        let control = request.encode().map_err(Error::Codec)?;
        let now = self.link.now().map_err(Error::Transport)?;
        if now == u64::MAX || self.last_clock.is_some_and(|last| now < last) {
            return Err(Error::Clock);
        }
        self.last_clock = Some(now);
        if !deadline.is_live(now) {
            return Err(Error::Deadline);
        }
        self.next_request += 1;
        if request.operation_id != 0 {
            self.next_operation += 1;
        }
        self.retained = Some(Pending::new(request).map_err(Error::Codec)?);
        let response = match self
            .link
            .exchange(request.request_id, &control, bulk, deadline)
        {
            Ok(response) => response,
            Err(error) => {
                self.retained.as_mut().unwrap().timeout();
                return Err(Error::Transport(error));
            }
        };
        let response = match self.retained.as_mut().unwrap().observe(&response, 0) {
            Ok(response) => response,
            Err(error) => {
                self.retained.as_mut().unwrap().timeout();
                return Err(Error::Codec(error));
            }
        };
        if !self.retained.as_ref().unwrap().completion_observed() {
            return Ok(Completion { request, response });
        }
        if response.outcome == Outcome::Completed && matches!(method, Method::Read { .. }) {
            let length = response.length as usize;
            if response
                .offset
                .checked_add(response.length)
                .is_none_or(|end| end > response.file_length)
            {
                self.retained.as_mut().unwrap().timeout();
                return Err(Error::Bounds);
            }
            if let Err(error) = self.link.read_bulk(&mut read_out[..length]) {
                // Preserve the request even though control arrived; caller data
                // was not verified and this link cannot safely be reused.
                return Err(Error::Transport(error));
            }
            if <[u8; 32]>::from(Sha256::digest(&read_out[..length])) != response.digest {
                return Err(Error::Digest);
            }
        }
        self.retained = None;
        Ok(Completion { request, response })
    }
}

#[cfg(test)]
mod tests;
