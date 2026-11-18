//! One bounded developer fixture transaction. DNS is diagnostic; it never
//! selects the independently fixed TCP destination. This is plaintext HTTP,
//! not TLS, peer identity, download admission or update trust.
use super::client::{Client, Error as ClientError};
use ev_net_driver::{protocol::Window, pump::Transport};
use ev_userspace_contract::root_v4::catalogue::NetworkPolicy;
pub const REQUEST: &[u8] = b"GET /hello HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n";
pub const BODY: &[u8] = b"Evrosion network fixture v1\n";
// Reference tick policy, not a calibrated wall-time or delivery guarantee.
// A quiescent Pending reply permits a later distinct query, never busy polling
// or replay of an accepted unknown request within the original transaction cut.
const PENDING_POLL_TICKS: u64 = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub stage: u8,
    pub result: u8,
    pub argument: u32,
}
impl Progress {
    pub fn encode(self) -> [u8; 8] {
        let mut b = [b'N', b'W', self.stage, self.result, 0, 0, 0, 0];
        b[4..].copy_from_slice(&self.argument.to_le_bytes());
        b
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    New,
    Lease,
    Resolve,
    Query,
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
    Http,
    Client(ClientError),
}
pub struct Transfer {
    phase: Phase,
    cut: u64,
    last: u64,
    calls: u16,
    last_tcp: Option<u8>,
    poll_after: u64,
    written: usize,
    http: Http,
}
impl Default for Transfer {
    fn default() -> Self {
        Self::new()
    }
}
impl Transfer {
    pub const fn new() -> Self {
        Self {
            phase: Phase::New,
            cut: 0,
            last: 0,
            calls: 0,
            last_tcp: None,
            poll_after: 0,
            written: 0,
            http: Http::new(),
        }
    }
    pub fn started(&self) -> bool {
        self.phase != Phase::New
    }
    pub fn finished(&self) -> bool {
        matches!(self.phase, Phase::Complete | Phase::Failed)
    }
    pub fn succeeded(&self) -> bool {
        self.phase == Phase::Complete
    }
    /// Actual attempted phase steps; reaching the fixed cap does not prove an
    /// RPC/device failure or change its original aggregate deadline.
    pub fn calls(&self) -> u16 {
        self.calls
    }
    /// Last TCP value from an actual canonical successful Status response.
    /// It is historical observation, not a current liveness/authority claim.
    pub fn last_tcp(&self) -> Option<u8> {
        self.last_tcp
    }
    pub fn begin(&mut self, now: u64, cut: u64) -> Result<(), Error> {
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
        self.phase = Phase::Lease;
        Ok(())
    }
    pub fn stage(&self) -> u8 {
        match self.phase {
            Phase::New => 1,
            Phase::Lease => 2,
            Phase::Resolve | Phase::Query => 3,
            Phase::Connect | Phase::Connecting => 4,
            Phase::Write => 5,
            _ => 6,
        }
    }
    pub fn fail(&mut self) {
        self.phase = Phase::Failed;
    }
    pub fn step<W: Window, T: Transport>(
        &mut self,
        client: &mut Client<W, T>,
        policy: NetworkPolicy<'_>,
        now: u64,
    ) -> Result<Option<Progress>, Error> {
        let result = self.step_inner(client, policy, now);
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn step_inner<W: Window, T: Transport>(
        &mut self,
        client: &mut Client<W, T>,
        policy: NetworkPolicy<'_>,
        now: u64,
    ) -> Result<Option<Progress>, Error> {
        if now == u64::MAX || now < self.last {
            self.fail();
            return Err(Error::Clock);
        }
        self.last = now;
        if self.finished() || self.phase == Phase::New {
            return Ok(None);
        }
        if now >= self.cut {
            self.fail();
            return Err(Error::Expired);
        }
        if now < self.poll_after {
            return Ok(None);
        }
        self.poll_after = 0;
        self.calls = self
            .calls
            .checked_add(1)
            .filter(|n| *n <= 128)
            .ok_or(Error::Counter)?;
        let cut = now
            .checked_add(1024)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Clock)?
            .min(self.cut);
        let mut pending = false;
        let progress = match self.phase {
            Phase::Lease => {
                let (address, tcp, configured) = client.status(now, cut).map_err(Error::Client)?;
                self.last_tcp = Some(tcp);
                if configured {
                    self.phase = Phase::Resolve;
                    Some((2, u32::from_le_bytes(address)))
                } else {
                    pending = true;
                    None
                }
            }
            Phase::Resolve => {
                client
                    .resolve(policy.dns_name, now, cut)
                    .map_err(Error::Client)?;
                self.phase = Phase::Query;
                pending = true;
                None
            }
            Phase::Query => {
                if let Some(address) = client.query_result(now, cut).map_err(Error::Client)? {
                    self.phase = Phase::Connect;
                    Some((3, u32::from_le_bytes(address)))
                } else {
                    pending = true;
                    None
                }
            }
            Phase::Connect => {
                client.connect(policy, now, cut).map_err(Error::Client)?;
                self.phase = Phase::Connecting;
                pending = true;
                None
            }
            Phase::Connecting => {
                let (_, tcp, _) = client.status(now, cut).map_err(Error::Client)?;
                self.last_tcp = Some(tcp);
                if tcp == 4 {
                    self.phase = Phase::Write;
                    Some((4, u32::from(policy.remote_port)))
                } else {
                    pending = true;
                    None
                }
            }
            Phase::Write => {
                if let Some(n) = client
                    .write(&REQUEST[self.written..], now, cut)
                    .map_err(Error::Client)?
                {
                    self.written += n;
                    if self.written == REQUEST.len() {
                        self.phase = Phase::Read;
                        Some((5, self.written as u32))
                    } else {
                        None
                    }
                } else {
                    pending = true;
                    None
                }
            }
            Phase::Read => {
                if let Some(bytes) = client.read(now, cut).map_err(Error::Client)? {
                    if bytes.is_empty() {
                        self.http.finish()?;
                        self.phase = Phase::Complete;
                        Some((6, BODY.len() as u32))
                    } else {
                        self.http.push(bytes)?;
                        None
                    }
                } else {
                    pending = true;
                    None
                }
            }
            _ => None,
        };
        if pending {
            self.poll_after = now
                .checked_add(PENDING_POLL_TICKS.min(self.cut - now))
                .ok_or(Error::Clock)?;
        }
        Ok(progress.map(|(stage, argument)| Progress {
            stage,
            result: 0,
            argument,
        }))
    }
}
/// Incremental narrow HTTP framing. No second 1KiB response buffer or shared
/// reference survives a control call. Exact Content-Length and actual EOF are
/// both required; response bytes are bounded independently of TCP fragmentation.
struct Http {
    line: [u8; 128],
    line_len: usize,
    total: usize,
    body: usize,
    status: bool,
    length: bool,
    headers_done: bool,
}
impl Http {
    const fn new() -> Self {
        Self {
            line: [0; 128],
            line_len: 0,
            total: 0,
            body: 0,
            status: false,
            length: false,
            headers_done: false,
        }
    }
    fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        for &b in bytes {
            self.total = self
                .total
                .checked_add(1)
                .filter(|n| *n <= 1024)
                .ok_or(Error::Http)?;
            if !self.headers_done && self.total > 512 {
                return Err(Error::Http);
            }
            if self.headers_done {
                if BODY.get(self.body) != Some(&b) {
                    return Err(Error::Http);
                }
                self.body += 1;
            } else if b == b'\n' {
                if self.line_len == 0 || self.line[self.line_len - 1] != b'\r' {
                    return Err(Error::Http);
                }
                let line = &self.line[..self.line_len - 1];
                if line.contains(&b'\r') {
                    return Err(Error::Http);
                }
                if !self.status {
                    if line != b"HTTP/1.1 200 OK" && line != b"HTTP/1.0 200 OK" {
                        return Err(Error::Http);
                    }
                    self.status = true;
                } else if line.is_empty() {
                    if !self.length {
                        return Err(Error::Http);
                    }
                    self.headers_done = true;
                } else {
                    let colon = line
                        .iter()
                        .position(|b| *b == b':')
                        .filter(|n| *n != 0)
                        .ok_or(Error::Http)?;
                    let name = &line[..colon];
                    if !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-') {
                        return Err(Error::Http);
                    }
                    let value = line[colon + 1..].trim_ascii();
                    if name.eq_ignore_ascii_case(b"Content-Length") {
                        if self.length || value.is_empty() {
                            return Err(Error::Http);
                        }
                        let mut n = 0usize;
                        for b in value {
                            if !b.is_ascii_digit() {
                                return Err(Error::Http);
                            }
                            n = n
                                .checked_mul(10)
                                .and_then(|n| n.checked_add(usize::from(b - b'0')))
                                .filter(|n| *n <= BODY.len())
                                .ok_or(Error::Http)?;
                        }
                        if n != BODY.len() {
                            return Err(Error::Http);
                        }
                        self.length = true;
                    } else if name.eq_ignore_ascii_case(b"Transfer-Encoding")
                        || name.eq_ignore_ascii_case(b"Content-Encoding")
                    {
                        return Err(Error::Http);
                    }
                }
                self.line_len = 0;
            } else {
                if self.total > 512
                    || self.line_len == self.line.len()
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
        if self.headers_done && self.body == BODY.len() {
            Ok(())
        } else {
            Err(Error::Http)
        }
    }
}
#[cfg(test)]
mod tests;
