//! Owned loopback transport fixture. HTTP supplies no signing authority.
mod acquisition;
pub(crate) mod time_corruption;
mod time_relay;
use crate::build::Result;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
pub(crate) const HELLO: &[u8] = b"Evrosion network fixture v1\n";
const MAX_REQUEST: usize = 4096;
const CONNECTION_TIME: Duration = Duration::from_secs(2);
const RETAINED_EXCHANGES: usize = 32;
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct Exchange {
    pub request: Vec<u8>,
    /// Only bytes actually accepted by the owned TCP stream's write calls.
    pub response: Vec<u8>,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutation: Option<time_corruption::Mutation>,
}
#[derive(Clone, Debug, Default, serde::Serialize)]
pub(crate) struct Snapshot {
    pub observed: u64,
    pub completed: u64,
    pub omitted: u64,
    pub exchanges: Vec<Exchange>,
}
pub(crate) struct Fixture {
    stop: Arc<AtomicBool>,
    served: Arc<AtomicU64>,
    ledger: Arc<Mutex<Snapshot>>,
    worker: Option<JoinHandle<()>>,
    acquisition: Option<Arc<Mutex<acquisition::Routes>>>,
    #[cfg(test)]
    address: SocketAddr,
}
impl Fixture {
    pub(crate) fn acquisition_pending() -> Result<Self> {
        Self::start_mode(
            "127.0.0.1:8080".parse().unwrap(),
            time_relay::Relay::provider(),
            false,
            Some(Arc::new(Mutex::new(acquisition::Routes::pending()))),
        )
    }
    #[cfg(test)]
    pub(crate) fn acquisition_pending_for_tests() -> Result<(Self, SocketAddr)> {
        let fixture = Self::start_mode(
            "127.0.0.1:0".parse().unwrap(),
            time_relay::Relay::provider(),
            false,
            Some(Arc::new(Mutex::new(acquisition::Routes::pending()))),
        )?;
        let address = fixture.address;
        Ok((fixture, address))
    }
    #[cfg(test)]
    pub(crate) fn acquisition_for_tests(
        phase: crate::download_fixture::PhaseFixture,
    ) -> Result<(Self, SocketAddr)> {
        let routes = Arc::new(Mutex::new(acquisition::Routes::new(phase)?));
        let fixture = Self::start_mode(
            "127.0.0.1:0".parse().unwrap(),
            time_relay::Relay::provider(),
            false,
            Some(routes),
        )?;
        let address = fixture.address;
        Ok((fixture, address))
    }
    pub(crate) fn acquisition(phase: crate::download_fixture::PhaseFixture) -> Result<Self> {
        let routes = Arc::new(Mutex::new(acquisition::Routes::new(phase)?));
        Self::start_mode(
            "127.0.0.1:8080".parse().unwrap(),
            time_relay::Relay::provider(),
            false,
            Some(routes),
        )
    }
    pub(crate) fn replace_phase(&self, phase: crate::download_fixture::PhaseFixture) -> Result<()> {
        self.acquisition
            .as_ref()
            .ok_or("not an acquisition fixture")?
            .lock()
            .map_err(|_| "acquisition route owner unavailable")?
            .replace(phase)
    }
    pub(crate) fn acquisition_receipt(&self) -> Result<serde_json::Value> {
        Ok(self
            .acquisition
            .as_ref()
            .ok_or("not an acquisition fixture")?
            .lock()
            .map_err(|_| "acquisition route owner unavailable")?
            .receipt())
    }
    pub(crate) fn hello() -> Result<Self> {
        Self::start("127.0.0.1:8080".parse().unwrap())
    }
    pub(crate) fn corrupt_time() -> Result<Self> {
        Self::start_relay_mode(
            "127.0.0.1:8080".parse().unwrap(),
            time_relay::Relay::provider(),
            true,
        )
    }
    fn start(address: SocketAddr) -> Result<Self> {
        Self::start_with_relay(address, time_relay::Relay::provider())
    }
    fn start_with_relay(address: SocketAddr, relay: time_relay::Relay) -> Result<Self> {
        Self::start_relay_mode(address, relay, false)
    }
    fn start_relay_mode(
        address: SocketAddr,
        relay: time_relay::Relay,
        corrupt_time: bool,
    ) -> Result<Self> {
        Self::start_mode(address, relay, corrupt_time, None)
    }
    fn start_mode(
        address: SocketAddr,
        mut relay: time_relay::Relay,
        corrupt_time: bool,
        acquisition: Option<Arc<Mutex<acquisition::Routes>>>,
    ) -> Result<Self> {
        if !address.ip().is_loopback() {
            return Err("fixture requires loopback".into());
        }
        // Occupied ports refuse; never replace another service.
        let listener =
            TcpListener::bind(address).map_err(|e| format!("owned network fixture: {e}"))?;
        #[cfg(test)]
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let served = Arc::new(AtomicU64::new(0));
        let stopping = stop.clone();
        let counted = served.clone();
        let ledger = Arc::new(Mutex::new(Snapshot::default()));
        let recorded = ledger.clone();
        let serving = acquisition.clone();
        let worker = thread::Builder::new()
            .name("ev-network-fixture".into())
            .spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut client, peer)) => {
                            if peer.ip().is_loopback() {
                                let mut exchange = Exchange {
                                    request: Vec::new(),
                                    response: Vec::new(),
                                    error: None,
                                    mutation: None,
                                };
                                let outcome = respond(
                                    &mut client,
                                    &stopping,
                                    &mut exchange,
                                    &mut relay,
                                    corrupt_time,
                                    serving.as_ref(),
                                );
                                exchange.error = outcome.as_ref().err().cloned();
                                let Ok(mut log) = recorded.lock() else {
                                    break;
                                };
                                let Some(next) = log.observed.checked_add(1) else {
                                    break;
                                };
                                log.observed = next;
                                if outcome.is_ok() {
                                    let Some(next) = log.completed.checked_add(1) else {
                                        break;
                                    };
                                    log.completed = next;
                                    if counted
                                        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                                            n.checked_add(1)
                                        })
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                if log.exchanges.len() < RETAINED_EXCHANGES {
                                    log.exchanges.push(exchange);
                                } else {
                                    let Some(next) = log.omitted.checked_add(1) else {
                                        break;
                                    };
                                    log.omitted = next;
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10))
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            stop,
            served,
            ledger,
            worker: Some(worker),
            acquisition,
            #[cfg(test)]
            address,
        })
    }
    pub(crate) fn served(&self) -> u64 {
        self.served.load(Ordering::Acquire)
    }
    pub(crate) fn snapshot(&self) -> Result<Snapshot> {
        self.ledger
            .lock()
            .map(|l| l.clone())
            .map_err(|_| "fixture ledger unavailable".into())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn remaining(deadline: Instant, stop: &AtomicBool) -> Result<Duration> {
    if stop.load(Ordering::Acquire) {
        return Err("fixture stopping".into());
    }
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("fixture connection deadline".into());
    }
    Ok(left.min(Duration::from_millis(100)))
}
fn request_path(bytes: &[u8]) -> Result<&str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "fixture request notUTF8")?;
    if !text.is_ascii() || !text.ends_with("\r\n\r\n") {
        return Err("noncanonical request".into());
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    let fields: Vec<_> = lines.next().ok_or("no request")?.split(' ').collect();
    if fields.len() != 3
        || fields[0] != "GET"
        || !matches!(fields[2], "HTTP/1.0" | "HTTP/1.1")
        || !fields[1].starts_with('/')
        || fields[1].contains("..")
        || fields[1].len() > 128
        || !fields[1]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_'))
    {
        return Err("unsupported fixture request".into());
    }
    for line in lines {
        let (key, value) = line.split_once(':').ok_or("invalid header")?;
        if key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || key.eq_ignore_ascii_case("transfer-encoding")
            || (key.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            return Err("request body/header refused".into());
        }
    }
    Ok(fields[1])
}
fn respond(
    stream: &mut TcpStream,
    stop: &AtomicBool,
    exchange: &mut Exchange,
    relay: &mut time_relay::Relay,
    corrupt_time: bool,
    acquisition: Option<&Arc<Mutex<acquisition::Routes>>>,
) -> Result<()> {
    let started = Instant::now();
    let mut deadline = started
        .checked_add(CONNECTION_TIME)
        .ok_or("deadline overflow")?;
    let mut bytes = [0; MAX_REQUEST];
    let mut length = 0;
    loop {
        if length == bytes.len() {
            return Err("request bound exceeded".into());
        }
        stream
            .set_read_timeout(Some(remaining(deadline, stop)?))
            .map_err(|e| e.to_string())?;
        match stream.read(&mut bytes[length..]) {
            Ok(0) => return Err("incomplete request".into()),
            Ok(n) => {
                exchange
                    .request
                    .extend_from_slice(&bytes[length..length + n]);
                length += n;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e.to_string()),
        }
        if bytes[..length].windows(4).any(|v| v == b"\r\n\r\n") {
            break;
        }
    }
    let path = request_path(&bytes[..length])?;
    let relayed;
    let asset = if let Some(routes) = acquisition {
        routes
            .lock()
            .map_err(|_| "acquisition route owner unavailable")?
            .asset(path)?
    } else {
        None
    };
    let (status, body) = if path == "/hello" {
        ("200 OK", HELLO)
    } else if path.starts_with("/time/") {
        let nonce = time_relay::nonce(path)?;
        // Reserve part of the original connection cut for an ordinary failure
        // response. Neither retry nor time spent receiving renews the cut.
        let relay_deadline = deadline.min(Instant::now() + Duration::from_secs(1));
        match relay.query(&nonce, relay_deadline, stop) {
            Ok(packet) => {
                relayed = if corrupt_time {
                    let mutation = time_corruption::checked(&packet)?;
                    let bytes = mutation.mutated.clone();
                    exchange.mutation = Some(mutation);
                    bytes
                } else {
                    packet
                };
                ("200 OK", relayed.as_slice())
            }
            Err(_) => ("503 Service Unavailable", &b"time source unavailable\n"[..]),
        }
    } else if let Some(bytes) = asset.as_ref() {
        if path == acquisition::ARTIFACT_PATH {
            // Separate fixed body class, anchored at ORIGINAL handler start;
            // receiving/request work never renews this60s artifact cut.
            deadline = started
                .checked_add(Duration::from_secs(60))
                .ok_or("artifact deadline overflow")?;
        }
        ("200 OK", bytes.as_slice())
    } else {
        ("404 Not Found", &b"not found\n"[..])
    };
    let reply = [format!("HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes(), body].concat();
    let mut pending = reply.as_slice();
    while !pending.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline, stop)?))
            .map_err(|e| e.to_string())?;
        match stream.write(pending) {
            Ok(0) => return Err("peer closed".into()),
            Ok(n) => {
                exchange.response.extend_from_slice(&pending[..n]);
                pending = &pending[n..];
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_tcp_reply_has_exact_body_and_worker_joins_with_partial_client() {
        let fixture = Fixture::start("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut client = TcpStream::connect(fixture.address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .write_all(b"GET /hello HTTP/1.1\r\nHost: fixture\r\n\r\n")
            .unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(reply.ends_with(HELLO));
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let snapshot = fixture.snapshot().unwrap();
            if snapshot.completed == 1 {
                assert_eq!(snapshot.omitted, 0);
                assert_eq!(snapshot.exchanges.len(), 1);
                assert_eq!(
                    snapshot.exchanges[0].request,
                    b"GET /hello HTTP/1.1\r\nHost: fixture\r\n\r\n"
                );
                assert_eq!(snapshot.exchanges[0].response, reply);
                assert!(snapshot.exchanges[0].error.is_none());
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        let mut stalled = TcpStream::connect(fixture.address).unwrap();
        stalled.write_all(b"GET /hello HTTP/1.1\r\n").unwrap();
        let start = Instant::now();
        drop(fixture);
        assert!(start.elapsed() < Duration::from_secs(3));
    }
    #[test]
    fn request_shape_refuses_pipelining_bodies_and_ambiguous_paths() {
        for request in [
            "GET /../hello HTTP/1.1\r\n\r\n",
            "GET /%68ello HTTP/1.1\r\n\r\n",
            "GET /hello HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET /hello HTTP/1.1\r\nContent-Length: 1\r\n\r\nx",
            "GET /hello HTTP/1.1\r\n\r\nGET /hello HTTP/1.1\r\n\r\n",
            "POST /hello HTTP/1.1\r\n\r\n",
        ] {
            assert!(request_path(request.as_bytes()).is_err());
        }
    }
    #[test]
    fn http_time_route_preserves_public_nonce_and_exact_untrusted_udp_body() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let relay = time_relay::Relay::new(server.local_addr().unwrap());
        let responder = thread::spawn(move || {
            let mut actual = [0; 1025];
            let (n, peer) = server.recv_from(&mut actual).unwrap();
            let mut expected = [0; 1024];
            ev_time_proof::encode_relay_request(&[0x42; 32], &mut expected);
            assert_eq!(&actual[..n], expected);
            server
                .send_to(b"unauthenticated packet bytes", peer)
                .unwrap();
        });
        let fixture = Fixture::start_with_relay("127.0.0.1:0".parse().unwrap(), relay).unwrap();
        let request = format!(
            "GET /time/{} HTTP/1.1\r\nHost: fixture\r\n\r\n",
            "42".repeat(32)
        );
        let mut stream = TcpStream::connect(fixture.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"\r\n\r\nunauthenticated packet bytes"));
        responder.join().unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        loop {
            let snapshot = fixture.snapshot().unwrap();
            if snapshot.completed == 1 {
                assert_eq!(snapshot.exchanges[0].request, request.as_bytes());
                assert_eq!(snapshot.exchanges[0].response, response);
                break;
            }
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(5));
        }
    }
}
