//! Fixed-scope bounded HTTP object transport. Length/hash are raw-byte
//! identities, never publisher, executable or release authorization.
//! One caller-owned private chunk is retained/checked across ordinary steps;
//! no shared ClientWindow reference survives a protected call.
mod http;
use super::client::{Client, Error as ClientError};
use ev_net_driver::{protocol::Window, pump::Transport};
use ev_userspace_contract::root_v4::catalogue::NetworkPolicy;
use sha2::{Digest, Sha256};

pub const CHUNK_BYTES: usize = 4096;
pub const MAX_DOWNLOAD_TICKS: u64 = 65536;
pub const MAX_CALLS: u16 = 2048;
const POLL_TICKS: u64 = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    Timestamp,
    Snapshot,
    Targets,
    Artifact,
}
impl Path {
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Timestamp => b"/release/timestamp.bin",
            Self::Snapshot => b"/release/snapshot.bin",
            Self::Targets => b"/release/targets.bin",
            Self::Artifact => b"/artifacts/hello.zion",
        }
    }
    pub const fn maximum(self) -> u64 {
        match self {
            Self::Timestamp | Self::Snapshot => crate::native_acquisition::LINK_BUFFER as u64,
            Self::Targets => crate::native_acquisition::TARGET_BUFFER as u64,
            Self::Artifact => ev_content_store::MAX_OBJECT_BYTES,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expectation {
    /// Bounded untrusted metadata whose identity is not independently known.
    Bounded,
    /// May originate in parsed UNTRUSTED metadata. It is no authorization.
    Exact { length: u64, sha256: [u8; 32] },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Waiting,
    Headers {
        length: u64,
    },
    Chunk {
        offset: u64,
        length: usize,
    },
    Complete {
        length: u64,
        sha256: [u8; 32],
    },
    /// Ordinary TCP Closed only. This never proves NIC/device quiescence.
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    State,
    Clock,
    Expired,
    Counter,
    Http,
    Length,
    Hash,
    Buffer,
    Lease,
    Client(ClientError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    New,
    Close,
    Closing,
    Resolve,
    Query,
    Connect,
    Connecting,
    Write,
    Read,
    FinalClose,
    FinalClosing,
    Complete,
    Cancelled,
    Failed,
}
pub struct Download {
    phase: Phase,
    path: Path,
    expected: Expectation,
    cut: u64,
    last: u64,
    poll_after: u64,
    calls: u16,
    last_tcp: Option<u8>,
    resolved: Option<[u8; 4]>,
    written: usize,
    header_pending: bool,
    header_accepted: bool,
    chunk_pending: bool,
    used: usize,
    consumed: u64,
    chunk_digest: [u8; 32],
    clear_chunk: bool,
    http: http::Http,
    hash: Option<Sha256>,
    identity: Option<[u8; 32]>,
    cancelling: bool,
    fenced: bool,
}
impl Default for Download {
    fn default() -> Self {
        Self::new()
    }
}
impl Download {
    pub const fn new() -> Self {
        Self {
            phase: Phase::New,
            path: Path::Timestamp,
            expected: Expectation::Bounded,
            cut: 0,
            last: 0,
            poll_after: 0,
            calls: 0,
            last_tcp: None,
            resolved: None,
            written: 0,
            header_pending: false,
            header_accepted: false,
            chunk_pending: false,
            used: 0,
            consumed: 0,
            chunk_digest: [0; 32],
            clear_chunk: true,
            http: http::Http::new(),
            hash: None,
            identity: None,
            cancelling: false,
            fenced: false,
        }
    }
    pub fn begin(
        &mut self,
        path: Path,
        expected: Expectation,
        now: u64,
        cut: u64,
    ) -> Result<(), Error> {
        if self.phase != Phase::New {
            return Err(Error::State);
        }
        if now == u64::MAX || cut == u64::MAX || cut <= now || cut - now > MAX_DOWNLOAD_TICKS {
            return Err(Error::Clock);
        }
        if path == Path::Artifact && matches!(expected, Expectation::Bounded) {
            return Err(Error::Length);
        }
        if let Expectation::Exact { length, .. } = expected
            && (length == 0 || length > path.maximum())
        {
            return Err(Error::Length);
        }
        self.path = path;
        self.expected = expected;
        self.last = now;
        self.cut = cut;
        self.hash = Some(Sha256::new());
        self.phase = Phase::Close;
        Ok(())
    }
    fn observe(&mut self, now: u64) -> Result<(), Error> {
        if now == u64::MAX || now < self.last {
            self.fenced = true;
            self.phase = Phase::Failed;
            return Err(Error::Clock);
        }
        self.last = now;
        if now >= self.cut {
            self.fenced = true;
            self.phase = Phase::Failed;
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub fn calls(&self) -> u16 {
        self.calls
    }
    pub fn received(&self) -> u64 {
        self.http.received()
    }
    pub fn length(&self) -> Option<u64> {
        self.http.length()
    }
    pub fn last_tcp(&self) -> Option<u8> {
        self.last_tcp
    }
    /// Fresh DNS observation only. The reference profile intentionally
    /// separates diagnostic example.org from the fixed authorized fixture IP.
    pub fn resolved(&self) -> Option<[u8; 4]> {
        self.resolved
    }
    pub fn acknowledge_headers(&mut self, now: u64) -> Result<(), Error> {
        self.observe(now)?;
        if self.phase != Phase::Read || !self.header_pending || self.header_accepted {
            return Err(Error::State);
        }
        self.header_pending = false;
        self.header_accepted = true;
        Ok(())
    }
    pub fn consume_chunk(&mut self, chunk: &[u8; CHUNK_BYTES], now: u64) -> Result<(), Error> {
        self.observe(now)?;
        if self.phase != Phase::Read || !self.chunk_pending || self.used == 0 {
            return Err(Error::State);
        }
        if <[u8; 32]>::from(Sha256::digest(&chunk[..self.used])) != self.chunk_digest {
            self.phase = Phase::Failed;
            return Err(Error::Buffer);
        }
        self.consumed = self
            .consumed
            .checked_add(self.used as u64)
            .ok_or(Error::Counter)?;
        self.used = 0;
        self.chunk_pending = false;
        self.clear_chunk = true;
        Ok(())
    }
    /// Cancels this download permanently. It can only close an already
    /// quiescent Client before the ORIGINAL cut; an unknown Client stays pinned.
    pub fn cancel(&mut self, now: u64) -> Result<(), Error> {
        if self.fenced
            || self.cancelling
            || matches!(self.phase, Phase::New | Phase::Complete | Phase::Cancelled)
        {
            return Err(Error::State);
        }
        self.observe(now)?;
        self.cancelling = true;
        self.header_pending = false;
        self.chunk_pending = false;
        self.phase = Phase::FinalClose;
        self.poll_after = 0;
        Ok(())
    }
    pub fn step<W: Window, T: Transport>(
        &mut self,
        client: &mut Client<W, T>,
        scope: NetworkPolicy<'_>,
        now: u64,
        chunk: &mut [u8; CHUNK_BYTES],
    ) -> Result<Event, Error> {
        let result = self.step_inner(client, scope, now, chunk);
        if result.is_err() {
            self.fenced |= matches!(result, Err(Error::Clock | Error::Expired | Error::Counter));
            self.phase = Phase::Failed;
        }
        result
    }
    fn step_inner<W: Window, T: Transport>(
        &mut self,
        client: &mut Client<W, T>,
        scope: NetworkPolicy<'_>,
        now: u64,
        chunk: &mut [u8; CHUNK_BYTES],
    ) -> Result<Event, Error> {
        if self.phase == Phase::New || self.phase == Phase::Failed {
            return Err(Error::State);
        }
        self.observe(now)?;
        if self.phase == Phase::Complete {
            return Ok(Event::Complete {
                length: self.http.received(),
                sha256: self.identity.ok_or(Error::State)?,
            });
        }
        if self.phase == Phase::Cancelled {
            return Ok(Event::Cancelled);
        }
        if client.quarantined() {
            return Err(Error::Client(ClientError::Quarantined));
        }
        if self.clear_chunk {
            chunk.fill(0);
            self.clear_chunk = false;
        }
        if self.used != 0
            && <[u8; 32]>::from(Sha256::digest(&chunk[..self.used])) != self.chunk_digest
        {
            return Err(Error::Buffer);
        }
        if self.header_pending || self.chunk_pending || now < self.poll_after {
            return Ok(Event::Waiting);
        }
        if self.phase == Phase::Read
            && self.header_accepted
            && self.used != 0
            && (self.used == CHUNK_BYTES || self.http.length() == Some(self.http.received()))
        {
            self.chunk_pending = true;
            return Ok(Event::Chunk {
                offset: self.consumed,
                length: self.used,
            });
        }
        self.calls = self
            .calls
            .checked_add(1)
            .filter(|n| *n <= MAX_CALLS)
            .ok_or(Error::Counter)?;
        let cut = now
            .checked_add(1024)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Clock)?
            .min(self.cut);
        let mut pending = false;
        match self.phase {
            Phase::Close | Phase::FinalClose => {
                client.close(now, cut).map_err(Error::Client)?;
                self.phase = if self.phase == Phase::Close {
                    Phase::Closing
                } else {
                    Phase::FinalClosing
                };
                pending = true;
            }
            Phase::Closing | Phase::FinalClosing => {
                let (_, tcp, lease) = client.status(now, cut).map_err(Error::Client)?;
                self.last_tcp = Some(tcp);
                if tcp == 0 {
                    self.phase = if self.phase == Phase::Closing {
                        if !lease {
                            return Err(Error::Lease);
                        }
                        Phase::Resolve
                    } else if self.cancelling {
                        Phase::Cancelled
                    } else {
                        Phase::Complete
                    };
                } else {
                    pending = true;
                }
            }
            Phase::Resolve => {
                client
                    .resolve(scope.dns_name, now, cut)
                    .map_err(Error::Client)?;
                self.phase = Phase::Query;
                pending = true;
            }
            Phase::Query => {
                if let Some(ip) = client.query_result(now, cut).map_err(Error::Client)? {
                    self.resolved = Some(ip);
                    self.phase = Phase::Connect;
                } else {
                    pending = true;
                }
            }
            Phase::Connect => {
                client.connect(scope, now, cut).map_err(Error::Client)?;
                self.phase = Phase::Connecting;
                pending = true;
            }
            Phase::Connecting => {
                let (_, tcp, lease) = client.status(now, cut).map_err(Error::Client)?;
                if !lease {
                    return Err(Error::Lease);
                }
                self.last_tcp = Some(tcp);
                if tcp == 4 {
                    self.phase = Phase::Write
                } else {
                    pending = true;
                }
            }
            Phase::Write => {
                let request = [
                    b"GET ".as_slice(),
                    self.path.bytes(),
                    b" HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n".as_slice(),
                ];
                let mut bytes = [0; 128];
                let mut n = 0;
                for part in request {
                    bytes[n..n + part.len()].copy_from_slice(part);
                    n += part.len();
                }
                if let Some(done) = client
                    .write(&bytes[self.written..n], now, cut)
                    .map_err(Error::Client)?
                {
                    self.written += done;
                    if self.written == n {
                        self.phase = Phase::Read
                    }
                } else {
                    pending = true;
                }
            }
            Phase::Read => {
                let capacity = 1024.min(CHUNK_BYTES - self.used) as u16;
                if let Some(bytes) = client
                    .read_limit(capacity, now, cut)
                    .map_err(Error::Client)?
                {
                    if bytes.is_empty() {
                        self.http.finish()?;
                        if self.used != 0 || self.consumed != self.http.received() {
                            return Err(Error::State);
                        }
                        let hash: [u8; 32] =
                            self.hash.take().ok_or(Error::State)?.finalize().into();
                        if let Expectation::Exact { sha256, .. } = self.expected
                            && sha256 != hash
                        {
                            return Err(Error::Hash);
                        }
                        self.identity = Some(hash);
                        self.phase = Phase::FinalClose;
                    } else {
                        let before = self.used;
                        let had_headers = self.http.length().is_some();
                        self.http.push(
                            bytes,
                            self.path.maximum(),
                            self.expected,
                            chunk,
                            &mut self.used,
                        )?;
                        self.hash
                            .as_mut()
                            .ok_or(Error::State)?
                            .update(&chunk[before..self.used]);
                        self.chunk_digest = Sha256::digest(&chunk[..self.used]).into();
                        if !had_headers && self.http.length().is_some() {
                            self.header_pending = true;
                            return Ok(Event::Headers {
                                length: self.http.length().unwrap(),
                            });
                        }
                    }
                } else {
                    pending = true;
                }
            }
            _ => return Err(Error::State),
        }
        if pending {
            self.poll_after = now
                .checked_add(POLL_TICKS.min(self.cut - now))
                .ok_or(Error::Clock)?;
        }
        match self.phase {
            Phase::Complete => Ok(Event::Complete {
                length: self.http.received(),
                sha256: self.identity.ok_or(Error::State)?,
            }),
            Phase::Cancelled => Ok(Event::Cancelled),
            _ => Ok(Event::Waiting),
        }
    }
}
#[cfg(test)]
mod tests;
