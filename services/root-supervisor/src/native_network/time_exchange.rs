//! Bounded untrusted HTTP relay transport, not time verification/qualification.
//! Uses the same exclusive Client505 owner and actual scoped TCP destination.
pub mod diagnostics;
use super::client::{Client, Error as ClientError};
use ev_net_driver::{protocol::Window, pump::Transport};
use ev_userspace_contract::root_v4::catalogue::NetworkPolicy;
pub const MAX_BODY: usize = ev_time_proof::MAX_REPLY_BYTES;
const PREFIX: &[u8] = b"GET /time/";
const SUFFIX: &[u8] = b" HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n";
// Actual monotonic ticks under the existing cut, never a wall-time guarantee.
const PENDING_POLL_TICKS: u64 = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    New,
    Close,
    Closing,
    Ready,
    Connect,
    Connecting,
    Write,
    Read,
    Complete,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Clock,
    Expired,
    Counter,
    State,
    Http,
    Client(ClientError),
}
/// Nonsecret observations of an actual failed exchange, never transport credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailureSnapshot {
    phase: u8,
    tcp: Option<u8>,
    calls: u8,
    error: u8,
    detail: u8,
}
impl FailureSnapshot {
    pub const fn phase(self) -> u8 {
        self.phase
    }
    pub const fn tcp(self) -> Option<u8> {
        self.tcp
    }
    pub const fn calls(self) -> u8 {
        self.calls
    }
    pub const fn error(self) -> (u8, u8) {
        (self.error, self.detail)
    }
}
fn phase_code(phase: Phase) -> u8 {
    match phase {
        Phase::New => 1,
        Phase::Close => 2,
        Phase::Closing => 3,
        Phase::Ready => 4,
        Phase::Connect => 5,
        Phase::Connecting => 6,
        Phase::Write => 7,
        Phase::Read => 8,
        Phase::Complete => 9,
        Phase::Failed => 10,
    }
}
fn error_code(error: Error) -> (u8, u8) {
    match error {
        Error::Clock => (1, 0),
        Error::Expired => (2, 0),
        Error::Counter => (3, 0),
        Error::State => (4, 0),
        Error::Http => (5, 0),
        Error::Client(error) => (
            6,
            match error {
                ClientError::Quarantined => 1,
                ClientError::Clock => 2,
                ClientError::Counter => 3,
                ClientError::Window => 4,
                ClientError::Transport => 5,
                ClientError::Response => 6,
                ClientError::Remote(_) => 7,
                ClientError::State => 8,
            },
        ),
    }
}
pub struct Exchange {
    phase: Phase,
    cut: u64,
    last: u64,
    calls: u16,
    poll_after: u64,
    request: [u8; 160],
    request_len: usize,
    written: usize,
    http: Http,
    last_tcp: Option<u8>,
    failure: Option<FailureSnapshot>,
}
impl Default for Exchange {
    fn default() -> Self {
        Self::new()
    }
}
impl Exchange {
    pub const fn new() -> Self {
        Self {
            phase: Phase::New,
            cut: 0,
            last: 0,
            calls: 0,
            poll_after: 0,
            request: [0; 160],
            request_len: 0,
            written: 0,
            http: Http::new(),
            last_tcp: None,
            failure: None,
        }
    }
    pub fn start(&mut self, now: u64, cut: u64) -> Result<(), Error> {
        if self.phase != Phase::New
            || now == u64::MAX
            || cut == u64::MAX
            || cut <= now
            || cut - now > 8192
        {
            return Err(Error::Clock);
        }
        self.last = now;
        self.cut = cut;
        self.phase = Phase::Close;
        Ok(())
    }
    pub fn ready(&self) -> bool {
        self.phase == Phase::Ready
    }
    /// Public relay bytes only. The caller's private affine verifier must own
    /// this nonce; passing bytes here can never create an authenticated result.
    pub fn publish(&mut self, nonce: &[u8; 32]) -> Result<(), Error> {
        if !self.ready() {
            return Err(Error::State);
        }
        self.request[..PREFIX.len()].copy_from_slice(PREFIX);
        for (i, b) in nonce.iter().enumerate() {
            self.request[PREFIX.len() + 2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
            self.request[PREFIX.len() + 2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
        }
        let start = PREFIX.len() + 64;
        self.request[start..start + SUFFIX.len()].copy_from_slice(SUFFIX);
        self.request_len = start + SUFFIX.len();
        self.phase = Phase::Connect;
        Ok(())
    }
    pub fn response(&self) -> Option<&[u8]> {
        (self.phase == Phase::Complete).then(|| self.http.body())
    }
    pub fn terminal(&self) -> bool {
        matches!(self.phase, Phase::Complete | Phase::Failed)
    }
    pub const fn failure(&self) -> Option<FailureSnapshot> {
        self.failure
    }
    pub fn abandon(&mut self) {
        self.phase = Phase::Failed;
    }
    pub fn step<W: Window, T: Transport>(
        &mut self,
        client: &mut Client<W, T>,
        policy: NetworkPolicy<'_>,
        now: u64,
    ) -> Result<(), Error> {
        let result = self.inner(client, policy, now);
        if let Err(error) = result {
            // Preserve the failure point before abandon changes the phase.
            // No additional RPC, clock or shared-window access is performed.
            if self.failure.is_none() {
                let (error, detail) = error_code(error);
                self.failure = Some(FailureSnapshot {
                    phase: phase_code(self.phase),
                    tcp: self.last_tcp,
                    calls: self.calls as u8,
                    error,
                    detail,
                });
            }
            self.abandon();
        }
        result
    }
    fn inner<W: Window, T: Transport>(
        &mut self,
        client: &mut Client<W, T>,
        policy: NetworkPolicy<'_>,
        now: u64,
    ) -> Result<(), Error> {
        if now == u64::MAX || now < self.last {
            return Err(Error::Clock);
        }
        self.last = now;
        if self.terminal() || self.phase == Phase::New {
            return Ok(());
        }
        if now >= self.cut {
            return Err(Error::Expired);
        }
        if self.ready() {
            return Ok(());
        }
        if now < self.poll_after {
            return Ok(());
        }
        self.poll_after = 0;
        self.calls = self
            .calls
            .checked_add(1)
            .filter(|n| *n <= 128)
            .ok_or(Error::Counter)?;
        let cut = now
            .checked_add(1024)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Clock)?
            .min(self.cut);
        let mut pending = false;
        match self.phase {
            Phase::Close => {
                client.close(now, cut).map_err(Error::Client)?;
                self.phase = Phase::Closing;
                pending = true;
            }
            Phase::Closing => {
                let (_, tcp, _) = client.status(now, cut).map_err(Error::Client)?;
                self.last_tcp = Some(tcp);
                if tcp == 0 {
                    self.phase = Phase::Ready;
                } else {
                    pending = true;
                }
            }
            Phase::Connect => {
                client.connect(policy, now, cut).map_err(Error::Client)?;
                self.phase = Phase::Connecting;
                pending = true;
            }
            Phase::Connecting => {
                let (_, tcp, _) = client.status(now, cut).map_err(Error::Client)?;
                self.last_tcp = Some(tcp);
                if tcp == 4 {
                    self.phase = Phase::Write;
                } else {
                    pending = true;
                }
            }
            Phase::Write => {
                if let Some(n) = client
                    .write(&self.request[self.written..self.request_len], now, cut)
                    .map_err(Error::Client)?
                {
                    self.written += n;
                    if self.written == self.request_len {
                        self.phase = Phase::Read;
                    }
                } else {
                    pending = true;
                }
            }
            Phase::Read => {
                if let Some(bytes) = client.read(now, cut).map_err(Error::Client)? {
                    if bytes.is_empty() {
                        self.http.finish()?;
                        self.phase = Phase::Complete;
                    } else {
                        self.http.push(bytes)?;
                    }
                } else {
                    pending = true;
                }
            }
            _ => (),
        }
        if pending {
            self.poll_after = now
                .checked_add(PENDING_POLL_TICKS.min(self.cut - now))
                .ok_or(Error::Clock)?;
        }
        Ok(())
    }
}
/// Private immutable response copy: no view of ClientWindow survives an RPC.
/// This accepts only bounded Content-Length framing and requires actual EOF.
struct Http {
    line: [u8; 128],
    line_len: usize,
    total: usize,
    length: Option<usize>,
    used: usize,
    status: bool,
    headers: bool,
    bytes: [u8; MAX_BODY],
}
impl Http {
    const fn new() -> Self {
        Self {
            line: [0; 128],
            line_len: 0,
            total: 0,
            length: None,
            used: 0,
            status: false,
            headers: false,
            bytes: [0; MAX_BODY],
        }
    }
    fn body(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
    fn push(&mut self, input: &[u8]) -> Result<(), Error> {
        for &b in input {
            self.total = self
                .total
                .checked_add(1)
                .filter(|n| *n <= 512 + MAX_BODY)
                .ok_or(Error::Http)?;
            if self.headers {
                if self.used >= self.length.ok_or(Error::Http)? {
                    return Err(Error::Http);
                }
                self.bytes[self.used] = b;
                self.used += 1;
                continue;
            }
            if self.total > 512 {
                return Err(Error::Http);
            }
            if b == b'\n' {
                if self.line_len == 0 || self.line[self.line_len - 1] != b'\r' {
                    return Err(Error::Http);
                }
                let line = &self.line[..self.line_len - 1];
                if !self.status {
                    if line != b"HTTP/1.1 200 OK" {
                        return Err(Error::Http);
                    }
                    self.status = true;
                } else if line.is_empty() {
                    if self.length.is_none() {
                        return Err(Error::Http);
                    }
                    self.headers = true;
                } else {
                    let colon = line
                        .iter()
                        .position(|b| *b == b':')
                        .filter(|n| *n != 0)
                        .ok_or(Error::Http)?;
                    let name = &line[..colon];
                    let value = line[colon + 1..].trim_ascii();
                    if !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-') {
                        return Err(Error::Http);
                    }
                    if name.eq_ignore_ascii_case(b"Content-Length") {
                        if self.length.is_some() || value.is_empty() {
                            return Err(Error::Http);
                        }
                        let mut length = 0usize;
                        for b in value {
                            if !b.is_ascii_digit() {
                                return Err(Error::Http);
                            }
                            length = length
                                .checked_mul(10)
                                .and_then(|n| n.checked_add(usize::from(b - b'0')))
                                .filter(|n| *n <= MAX_BODY)
                                .ok_or(Error::Http)?;
                        }
                        if length == 0 {
                            return Err(Error::Http);
                        }
                        self.length = Some(length);
                    } else if name.eq_ignore_ascii_case(b"Transfer-Encoding")
                        || name.eq_ignore_ascii_case(b"Content-Encoding")
                    {
                        return Err(Error::Http);
                    }
                }
                self.line_len = 0;
            } else {
                if self.line_len == self.line.len()
                    || !(b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\r')
                {
                    return Err(Error::Http);
                }
                self.line[self.line_len] = b;
                self.line_len += 1;
            }
        }
        Ok(())
    }
    fn finish(&self) -> Result<(), Error> {
        if self.headers && self.length == Some(self.used) {
            Ok(())
        } else {
            Err(Error::Http)
        }
    }
}
#[cfg(test)]
mod tests;
