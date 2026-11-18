//! Owned finite HTTP peer. Pending acceptance is published before withholding
//! every response byte, independently of the guest's progress labels.
use crate::build::Result;
use serde::Serialize;
use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(super) const HELLO: &[u8] =
    b"GET /hello HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n";
pub(super) const PENDING: &[u8] =
    b"GET /pending HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n";
#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct Snapshot {
    pub accepted: u64,
    pub hello_completed: u64,
    pub pending_accepted: u64,
    pub response_bytes: u64,
    pub requests: Vec<Vec<u8>>,
    pub error: Option<String>,
}
impl Snapshot {
    /// The owned peer has completed only initial Hello and accepted the exact
    /// held request. Its Pending branch writes no bytes; the actual completed
    /// byte ledger must still equal precisely the one Hello response.
    pub(super) fn pending_withheld(&self) -> Result<()> {
        let body = crate::network_fixture::HELLO;
        let expected=format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).len()+body.len();
        if self.error.is_some()
            || self.accepted != 2
            || self.hello_completed != 1
            || self.pending_accepted != 1
            || self.requests != [HELLO.to_vec(), PENDING.to_vec()]
            || self.response_bytes != expected as u64
        {
            return Err("linkloss owned peer lacks exact accepted/no-response ledger".into());
        }
        Ok(())
    }
}
pub(super) struct Fixture {
    stop: Arc<AtomicBool>,
    actual: Arc<Mutex<Snapshot>>,
    worker: Option<JoinHandle<()>>,
}
impl Fixture {
    pub(super) fn start() -> Result<Self> {
        Self::at("127.0.0.1:8080".parse().unwrap()).map(|(f, _)| f)
    }
    fn at(address: SocketAddr) -> Result<(Self, SocketAddr)> {
        let listener =
            TcpListener::bind(address).map_err(|e| format!("negative owned HTTP bind: {e}"))?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let actual = Arc::new(Mutex::new(Snapshot::default()));
        let signal = stop.clone();
        let ledger = actual.clone();
        let worker = thread::spawn(move || {
            let result = (|| -> Result<()> {
                while !signal.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, peer)) => {
                            if !peer.ip().is_loopback() {
                                return Err("negative non-loopback peer".into());
                            }
                            {
                                let mut l =
                                    ledger.lock().map_err(|_| "negative fixture poisoned")?;
                                l.accepted += 1;
                                if l.accepted > 3 {
                                    return Err("negative fixture extra connection".into());
                                }
                            }
                            serve(&mut stream, &signal, &ledger)?;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10))
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }
                Ok(())
            })();
            if let Err(error) = result
                && let Ok(mut l) = ledger.lock()
            {
                l.error = Some(error);
            }
        });
        Ok((
            Self {
                stop,
                actual,
                worker: Some(worker),
            },
            address,
        ))
    }
    pub(super) fn snapshot(&self) -> Result<Snapshot> {
        self.actual
            .lock()
            .map(|l| l.clone())
            .map_err(|_| "negative fixture poisoned".into())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
fn serve(stream: &mut TcpStream, stop: &AtomicBool, ledger: &Mutex<Snapshot>) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_millis(20)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut request = Vec::new();
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("negative request deadline".into());
        }
        let mut buf = [0; 256];
        match stream.read(&mut buf) {
            Ok(0) => return Err("negative request truncated".into()),
            Ok(n) => {
                request.extend_from_slice(&buf[..n]);
                if request.len() > 1024 {
                    return Err("negative request bound".into());
                }
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    if request != HELLO && request != PENDING {
        return Err("negative fixture exact request differs".into());
    }
    {
        let mut l = ledger.lock().map_err(|_| "negative fixture poisoned")?;
        l.requests.push(request.clone());
        if request == PENDING {
            l.pending_accepted += 1;
        }
    }
    if request == PENDING {
        while !stop.load(Ordering::Acquire) {
            let mut b = [0; 1];
            match stream.read(&mut b) {
                Ok(0) => break,
                Ok(_) => return Err("negative pending peer sent additional bytes".into()),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    break;
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
        return Ok(());
    }
    let body = crate::network_fixture::HELLO;
    let response=[format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes(),body].concat();
    stream.write_all(&response).map_err(|e| e.to_string())?;
    {
        let mut l = ledger.lock().map_err(|_| "negative fixture poisoned")?;
        l.hello_completed += 1;
        l.response_bytes += response.len() as u64;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_is_observed_before_any_reply_and_worker_joins() {
        let (f, a) = Fixture::at("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut s = TcpStream::connect(a).unwrap();
        s.write_all(PENDING).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while f.snapshot().unwrap().pending_accepted == 0 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        let actual = f.snapshot().unwrap();
        assert_eq!(actual.requests, vec![PENDING.to_vec()]);
        assert_eq!(actual.response_bytes, 0);
        assert_eq!(actual.hello_completed, 0);
        s.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        assert!(matches!(
            s.read(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        drop(f);
    }
    #[test]
    fn linkloss_exact_two_connection_ledger_proves_pending_has_no_response_bytes() {
        let (fixture, address) = Fixture::at("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut hello = TcpStream::connect(address).unwrap();
        hello
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        hello.write_all(HELLO).unwrap();
        let mut response = Vec::new();
        hello.read_to_end(&mut response).unwrap();
        let mut pending = TcpStream::connect(address).unwrap();
        pending.write_all(PENDING).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while fixture.snapshot().unwrap().pending_accepted == 0 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        let actual = fixture.snapshot().unwrap();
        assert_eq!(actual.response_bytes, response.len() as u64);
        actual.pending_withheld().unwrap();
        pending
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        assert!(matches!(
            pending.read(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        let mut bad = actual.clone();
        bad.response_bytes += 1;
        assert!(bad.pending_withheld().is_err());
        let mut bad = actual.clone();
        bad.requests.swap(0, 1);
        assert!(bad.pending_withheld().is_err());
        let mut bad = actual;
        bad.accepted += 1;
        assert!(bad.pending_withheld().is_err());
        drop(fixture);
    }
}
