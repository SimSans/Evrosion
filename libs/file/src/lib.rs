//! Trusted userspace File/Object gateway over one exclusively owned Store.
//! Endpoint identity comes from the actual successful kernel receive route,
//! never client packet fields. This library does not itself mint capabilities.
#![no_std]
#![forbid(unsafe_code)]
pub mod desktop;
use ev_store::{ObjectId, OperationId, Request as StoreRequest, SectorIo, Store};
pub use ev_userspace_contract::file::{DecodeError, ErrorCode, Payload, Request, Response};

pub const ENVELOPE_HEADER: usize = 32;
pub const MAX_PAYLOAD: usize = 224;
const MAGIC: &[u8; 8] = b"EVFILE01";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    Length,
    Magic,
    Version,
    Reserved,
    Counter,
    Operation,
}
/// Internal on-disk envelope, not a client wire frame or authority token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope<'a> {
    counter: u64,
    global_operation: u64,
    payload: &'a [u8],
}
impl<'a> Envelope<'a> {
    /// Initial provisioning has no mutation receipt: counter/global op are0.
    /// Only a trusted formatter may use these bytes on a NEW volume.
    pub fn initial(payload: &'a [u8]) -> Result<Self, EnvelopeError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(EnvelopeError::Length);
        }
        Ok(Self {
            counter: 0,
            global_operation: 0,
            payload,
        })
    }
    pub fn decode(bytes: &'a [u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < ENVELOPE_HEADER || bytes.len() > ev_store::PAYLOAD_BYTES {
            return Err(EnvelopeError::Length);
        }
        if &bytes[..8] != MAGIC {
            return Err(EnvelopeError::Magic);
        }
        if bytes[8..10] != VERSION.to_le_bytes() {
            return Err(EnvelopeError::Version);
        }
        let length = usize::from(u16::from_le_bytes([bytes[10], bytes[11]]));
        if length > MAX_PAYLOAD || ENVELOPE_HEADER + length != bytes.len() {
            return Err(EnvelopeError::Length);
        }
        if bytes[12..16].iter().any(|b| *b != 0) {
            return Err(EnvelopeError::Reserved);
        }
        let counter = u64::from_le_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| EnvelopeError::Counter)?,
        );
        let global_operation = u64::from_le_bytes(
            bytes[24..32]
                .try_into()
                .map_err(|_| EnvelopeError::Operation)?,
        );
        if counter == u64::MAX || (counter == 0) != (global_operation == 0) {
            return Err(EnvelopeError::Counter);
        }
        if global_operation != 0 && OperationId::new(global_operation).is_none() {
            return Err(EnvelopeError::Operation);
        }
        Ok(Self {
            counter,
            global_operation,
            payload: &bytes[32..],
        })
    }
    pub fn encode(&self, out: &mut [u8; ev_store::PAYLOAD_BYTES]) -> usize {
        out.fill(0);
        out[..8].copy_from_slice(MAGIC);
        out[8..10].copy_from_slice(&VERSION.to_le_bytes());
        out[10..12].copy_from_slice(&(self.payload.len() as u16).to_le_bytes());
        out[16..24].copy_from_slice(&self.counter.to_le_bytes());
        out[24..32].copy_from_slice(&self.global_operation.to_le_bytes());
        out[32..32 + self.payload.len()].copy_from_slice(self.payload);
        ENVELOPE_HEADER + self.payload.len()
    }
    pub fn counter(&self) -> u64 {
        self.counter
    }
    /// Trusted service diagnostics only. Clients cannot supply or select this
    /// global operation; the logical response contains only their file counter.
    pub fn global_operation(&self) -> u64 {
        self.global_operation
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Immutable bindings to the actual retained RECEIVE capability handles. Kernel
/// receive must authorize them each time, including generation/revocation. These
/// numbers are not accepted from a client frame or diagnostic sender identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bindings {
    readonly: u64,
    read_write: u64,
}
impl Bindings {
    pub const fn new(readonly: u64, read_write: u64) -> Option<Self> {
        if readonly == 0 || read_write == 0 || readonly == read_write {
            None
        } else {
            Some(Self {
                readonly,
                read_write,
            })
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Denied,
    Malformed(DecodeError),
    InvalidCounter,
    Stale,
    Skipped,
    Conflict,
    Envelope(EnvelopeError),
    Backend(ev_store::Error<E>),
}
impl<E> Error<E> {
    /// A backend error does not imply nonexecution. After explicit backend
    /// recovery retry the SAME client counter and payload, never a fresh one.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Denied => ErrorCode::Denied,
            Self::Malformed(DecodeError::Counter) => ErrorCode::InvalidCounter,
            Self::Malformed(_) => ErrorCode::Malformed,
            Self::InvalidCounter => ErrorCode::InvalidCounter,
            Self::Stale => ErrorCode::Stale,
            Self::Skipped => ErrorCode::Skipped,
            Self::Conflict => ErrorCode::Conflict,
            Self::Envelope(_) => ErrorCode::Corrupt,
            Self::Backend(ev_store::Error::Io(_)) => ErrorCode::Io,
            Self::Backend(ev_store::Error::NeedsRecovery) => ErrorCode::NeedsRecovery,
            Self::Backend(ev_store::Error::Exhausted) => ErrorCode::Exhausted,
            Self::Backend(_) => ErrorCode::Corrupt,
        }
    }
}

/// One Store owner serializes all writes to this region. Cloning a backend or
/// transfer window does not supply volume exclusivity. Device idle/quiescence
/// and actual endpoint authority remain the trusted runtime's obligations.
pub struct Gateway<D: SectorIo> {
    store: Store<D>,
    bindings: Bindings,
}
impl<D: SectorIo> Gateway<D> {
    pub fn new(store: Store<D>, bindings: Bindings) -> Self {
        Self { store, bindings }
    }
    pub fn into_store(self) -> Store<D> {
        self.store
    }

    /// The service passes the capability it actually used for a successful
    /// kernel receive. The application protocol has no endpoint/object selector.
    /// Request is already a PRIVATE server snapshot, not a borrowed shared page.
    pub fn handle(
        &mut self,
        received_on: u64,
        request: Request,
        deadline: u64,
    ) -> Result<Response, Error<D::Error>> {
        let writable = if received_on == self.bindings.readonly {
            false
        } else if received_on == self.bindings.read_write {
            true
        } else {
            return Err(Error::Denied);
        };
        if matches!(request, Request::Replace { .. }) && !writable {
            return Err(Error::Denied);
        }
        if let Request::Replace { counter, .. } = request
            && (counter == 0 || counter == u64::MAX)
        {
            return Err(Error::InvalidCounter);
        }
        let mut bytes = [0; ev_store::PAYLOAD_BYTES];
        let length = self
            .store
            .read_mutable(ObjectId::user_data(), &mut bytes, deadline)
            .map_err(Error::Backend)?;
        let current = Envelope::decode(&bytes[..length]).map_err(Error::Envelope)?;
        match self.store.next_operation() {
            Ok(next) if current.global_operation >= next.get() => {
                return Err(Error::Envelope(EnvelopeError::Operation));
            }
            Ok(_) | Err(ev_store::Error::Exhausted) => (),
            Err(error) => return Err(Error::Backend(error)),
        }
        match request {
            Request::Read => Ok(Response::Read {
                counter: current.counter,
                payload: Payload::new(current.payload).map_err(Error::Malformed)?,
            }),
            Request::Replace { counter, payload } => {
                if counter < current.counter {
                    return Err(Error::Stale);
                }
                if counter == current.counter {
                    if payload.as_slice() != current.payload {
                        return Err(Error::Conflict);
                    }
                    // Stored atomic envelope is the receipt. Never ask the
                    // bounded global journal to replay an overwritten old ID.
                    return Ok(Response::Replaced {
                        counter,
                        replayed: true,
                    });
                }
                if current.counter.checked_add(1) != Some(counter) {
                    return Err(Error::Skipped);
                }
                let operation = self.store.next_operation().map_err(Error::Backend)?;
                let next = Envelope {
                    counter,
                    global_operation: operation.get(),
                    payload: payload.as_slice(),
                };
                let mut encoded = [0; ev_store::PAYLOAD_BYTES];
                let length = next.encode(&mut encoded);
                let receipt = self
                    .store
                    .execute(
                        operation,
                        StoreRequest::WriteMutable {
                            object: ObjectId::user_data(),
                            bytes: &encoded[..length],
                        },
                        deadline,
                    )
                    .map_err(Error::Backend)?;
                if receipt.operation != operation
                    || receipt.sequence != operation.get() + 1
                    || receipt.replayed
                {
                    return Err(Error::Envelope(EnvelopeError::Operation));
                }
                Ok(Response::Replaced {
                    counter,
                    replayed: false,
                })
            }
        }
    }
    /// Malformed framing is rejected before any backend read or mutation.
    pub fn handle_frame(
        &mut self,
        received_on: u64,
        frame: &[u8],
        deadline: u64,
    ) -> Result<Response, Error<D::Error>> {
        let request = Request::decode(frame).map_err(Error::Malformed)?;
        self.handle(received_on, request, deadline)
    }
}

#[cfg(test)]
mod tests;
