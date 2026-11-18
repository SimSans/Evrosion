//! Sole Root owner of ClientWindow and its protected route. No accepted call
//! is retried; an unknown result pins this owner until actual peer retirement.
use ev_net_driver::{
    control::{MAX_NAME, Notice, Operation, Packet, Status},
    protocol::Window,
    pump::Transport,
};
use ev_userspace_contract::root_v4::catalogue::NetworkPolicy;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Quarantined,
    Clock,
    Counter,
    Window,
    Transport,
    Response,
    Remote(Status),
    State,
}
impl Error {
    /// Nonsecret attempted-operation classification only, never an ACK or a
    /// window/device quiescence claim. Exact error values retain their fences.
    pub fn diagnostic(self, operation: Operation) -> Option<ev_net_driver::diagnostic::Diagnostic> {
        let (class, detail) = match self {
            Self::Quarantined => (1, 0),
            Self::Clock => (2, 0),
            Self::Counter => (3, 0),
            Self::Window => (4, 0),
            Self::Transport => (5, 0),
            Self::Response => (6, 0),
            Self::Remote(status) => (7, status as u8),
            Self::State => (8, 0),
        };
        ev_net_driver::diagnostic::Diagnostic::checked(3, operation as u8, class, detail, 0, 0)
    }
}

pub struct Client<W, T> {
    window: W,
    transport: T,
    packet: Packet,
    sequence: u32,
    failed: bool,
    stopped: bool,
    initialized: bool,
    shutdown_cut: Option<u64>,
    shutdown_steps: u16,
    last_operation: Option<Operation>,
}
impl<W: Window, T: Transport> Client<W, T> {
    pub fn new(window: W, transport: T) -> Self {
        Self {
            window,
            transport,
            packet: Packet::new(),
            sequence: 0,
            failed: false,
            stopped: false,
            initialized: false,
            shutdown_cut: None,
            shutdown_steps: 0,
            last_operation: None,
        }
    }
    pub fn quarantined(&self) -> bool {
        self.failed
    }
    pub fn last_operation(&self) -> Option<Operation> {
        self.last_operation
    }
    fn request(
        &mut self,
        operation: Operation,
        body: &[u8],
        now: u64,
        cut: u64,
    ) -> Result<Status, Error> {
        self.last_operation = Some(operation);
        if self.failed || self.stopped {
            return Err(Error::Quarantined);
        }
        if self.shutdown_cut.is_some() && operation != Operation::ShutdownStep {
            return Err(Error::Quarantined);
        }
        if cut == u64::MAX || cut <= now || cut - now > 1024 {
            return Err(Error::Clock);
        }
        self.failed = true;
        self.sequence = self
            .sequence
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .ok_or(Error::Counter)?;
        let notice = Notice {
            operation,
            sequence: self.sequence,
        };
        self.packet
            .write_request(&mut self.window, notice, body)
            .map_err(|_| Error::Window)?;
        let response = self
            .transport
            .call(notice.encode().map_err(|_| Error::Response)?, cut)
            .map_err(|_| Error::Transport)?;
        let status = notice
            .response_status(response)
            .map_err(|_| Error::Response)?;
        self.packet
            .read_response(&mut self.window, notice, status)
            .map_err(|_| Error::Response)?;
        if status == Status::Uncertain {
            return Err(Error::Remote(status));
        }
        self.failed = false;
        if !matches!(status, Status::Complete | Status::Pending) {
            return Err(Error::Remote(status));
        }
        Ok(status)
    }
    /// The seed must already come from the actual qualified provider. Neither
    /// this codec nor the service can qualify an entropy source from its bytes.
    pub fn initialize(
        &mut self,
        seed: &[u8; 8],
        policy: NetworkPolicy<'_>,
        now: u64,
        cut: u64,
    ) -> Result<(), Error> {
        if self.initialized {
            return Err(Error::State);
        }
        if policy.dns_name.len() > MAX_NAME {
            return Err(Error::Response);
        }
        let mut body = [0; 24 + MAX_NAME];
        body[..8].copy_from_slice(seed);
        body[8..12].copy_from_slice(&policy.allowed_ipv4);
        body[12..14].copy_from_slice(&policy.remote_port.to_le_bytes());
        body[14..16].copy_from_slice(&policy.local_port.to_le_bytes());
        body[16] = policy.dns_name.len() as u8;
        body[24..24 + policy.dns_name.len()].copy_from_slice(policy.dns_name.as_bytes());
        let result = self
            .request(
                Operation::Initialize,
                &body[..24 + policy.dns_name.len()],
                now,
                cut,
            )
            .and_then(|s| {
                if s == Status::Complete {
                    Ok(())
                } else {
                    Err(Error::Remote(s))
                }
            });
        // The DRBG's actual source seed is erased by its owner. This separate
        // protocol seed is not logged or deliberately retained after the call.
        body.fill(0);
        core::hint::black_box(&body);
        if result.is_ok() {
            self.initialized = true;
        }
        result
    }
    pub fn shutdown(&mut self, now: u64, cut: u64) -> Result<(), Error> {
        let status = self.request(Operation::Shutdown, &[], now, cut)?;
        if status != Status::Complete {
            self.failed = true;
            return Err(Error::Remote(status));
        }
        self.stopped = true;
        Ok(())
    }
    /// v2 begins one externally captured cleanup transaction. Pending is only
    /// a quiescent intermediate ACK, never a device-stop/reuse permission.
    pub fn shutdown_begin(&mut self, aggregate: u64, now: u64, cut: u64) -> Result<(), Error> {
        if self.shutdown_cut.is_some() {
            return Err(Error::State);
        }
        if aggregate == u64::MAX || aggregate <= now || aggregate - now > 8192 || cut > aggregate {
            return Err(Error::Clock);
        }
        if self.request(Operation::ShutdownBegin, &aggregate.to_le_bytes(), now, cut)?
            != Status::Pending
        {
            self.failed = true;
            return Err(Error::Response);
        }
        self.shutdown_cut = Some(aggregate);
        Ok(())
    }
    pub fn shutdown_step(&mut self, now: u64, cut: u64) -> Result<bool, Error> {
        let aggregate = self.shutdown_cut.ok_or(Error::State)?;
        if cut > aggregate {
            return Err(Error::Clock);
        }
        let status = self.request(Operation::ShutdownStep, &[], now, cut)?;
        let steps = self
            .shutdown_steps
            .checked_add(1)
            .filter(|n| *n <= 128)
            .ok_or_else(|| {
                self.failed = true;
                Error::Counter
            })?;
        if (status == Status::Complete) != (steps == 128)
            || !matches!(status, Status::Complete | Status::Pending)
        {
            self.failed = true;
            return Err(Error::Response);
        }
        self.shutdown_steps = steps;
        match status {
            Status::Pending => Ok(false),
            Status::Complete => {
                self.stopped = true;
                Ok(true)
            }
            _ => unreachable!(),
        }
    }
    pub fn source_failed(&mut self) {
        self.failed = true;
    }
    /// Each Pending is an explicit quiescent result. A later poll is a new
    /// operation/sequence, never a retry of an accepted unknown call.
    pub fn status(&mut self, now: u64, cut: u64) -> Result<([u8; 4], u8, bool), Error> {
        if self.request(Operation::Status, &[], now, cut)? != Status::Complete {
            return Err(Error::Response);
        }
        let b = self.packet.data();
        Ok((b[8..12].try_into().unwrap(), b[2], b[1] == 1))
    }
    pub fn resolve(&mut self, name: &str, now: u64, cut: u64) -> Result<(), Error> {
        self.request(Operation::Resolve, name.as_bytes(), now, cut)
            .map(|_| ())
    }
    pub fn query_result(&mut self, now: u64, cut: u64) -> Result<Option<[u8; 4]>, Error> {
        match self.request(Operation::QueryResult, &[], now, cut)? {
            Status::Pending => Ok(None),
            _ => Ok(Some(
                self.packet.data().try_into().map_err(|_| Error::Response)?,
            )),
        }
    }
    pub fn connect(&mut self, policy: NetworkPolicy<'_>, now: u64, cut: u64) -> Result<(), Error> {
        let mut address = [0; 6];
        address[..4].copy_from_slice(&policy.allowed_ipv4);
        address[4..].copy_from_slice(&policy.remote_port.to_le_bytes());
        self.request(Operation::Connect, &address, now, cut)
            .map(|_| ())
    }
    pub fn write(&mut self, bytes: &[u8], now: u64, cut: u64) -> Result<Option<usize>, Error> {
        match self.request(Operation::Write, bytes, now, cut)? {
            Status::Pending => Ok(None),
            _ => {
                let n = usize::from(u16::from_le_bytes(
                    self.packet.data().try_into().map_err(|_| Error::Response)?,
                ));
                if n == 0 || n > bytes.len() {
                    self.failed = true;
                    return Err(Error::Response);
                }
                Ok(Some(n))
            }
        }
    }
    pub fn read(&mut self, now: u64, cut: u64) -> Result<Option<&[u8]>, Error> {
        self.read_limit(1024, now, cut)
    }
    /// Bounded private-consumer capacity. Existing callers retain the exact
    ///1024-byte request; a stream can avoid accepting more than its free chunk.
    pub fn read_limit(&mut self, limit: u16, now: u64, cut: u64) -> Result<Option<&[u8]>, Error> {
        if !(1..=1024).contains(&limit) {
            return Err(Error::State);
        }
        match self.request(Operation::Read, &limit.to_le_bytes(), now, cut)? {
            Status::Pending => Ok(None),
            _ => {
                if self.packet.data().len() > usize::from(limit) {
                    self.failed = true;
                    return Err(Error::Response);
                }
                Ok(Some(self.packet.data()))
            }
        }
    }
    /// Initiate ordinary TCP close; completion is not a Closed-state or device
    /// quiescence claim. The next transaction must observe actual Closed.
    pub fn close(&mut self, now: u64, cut: u64) -> Result<(), Error> {
        if self.request(Operation::Close, &[], now, cut)? != Status::Complete {
            return Err(Error::Response);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(feature = "native-network-negative")]
mod negative;
