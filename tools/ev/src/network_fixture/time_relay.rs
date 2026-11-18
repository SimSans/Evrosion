//! Fixed-destination, untrusted transport. The guest authenticates every reply.
use super::{Result, remaining};
use std::{
    net::{SocketAddr, UdpSocket},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

pub(super) struct Relay {
    destination: SocketAddr,
    last_query: Option<Instant>,
}
impl Relay {
    pub(super) fn provider() -> Self {
        // Observed Cloudflare draft11 endpoint. Routing cannot change the key
        // independently pinned by the guest. No ambient DNS/key discovery.
        Self::new("162.159.200.1:2003".parse().unwrap())
    }
    pub(super) fn new(destination: SocketAddr) -> Self {
        Self {
            destination,
            last_query: None,
        }
    }
    pub(super) fn query(
        &mut self,
        nonce: &[u8; 32],
        deadline: Instant,
        stop: &AtomicBool,
    ) -> Result<Vec<u8>> {
        let now = Instant::now();
        remaining(deadline, stop)?;
        if self
            .last_query
            .is_some_and(|last| now.duration_since(last) < Duration::from_secs(1))
        {
            return Err("time relay rate bound".into());
        }
        // An attempted publication consumes this rate interval even on failure.
        self.last_query = Some(now);
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        socket
            .connect(self.destination)
            .map_err(|e| e.to_string())?;
        socket
            .set_write_timeout(Some(remaining(deadline, stop)?))
            .map_err(|e| e.to_string())?;
        let mut request = [0; 1024];
        ev_time_proof::encode_relay_request(nonce, &mut request);
        // No retry of a possibly accepted datagram.
        if socket.send(&request).map_err(|e| e.to_string())? != request.len() {
            return Err("time relay short send".into());
        }
        // One extra byte makes truncation of any oversized packet a refusal.
        let mut response = [0; ev_time_proof::MAX_REPLY_BYTES + 1];
        loop {
            socket
                .set_read_timeout(Some(remaining(deadline, stop)?))
                .map_err(|e| e.to_string())?;
            match socket.recv(&mut response) {
                Ok(n) if (1..=ev_time_proof::MAX_REPLY_BYTES).contains(&n) => {
                    return Ok(response[..n].to_vec());
                }
                Ok(_) => return Err("time relay reply bound".into()),
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
    }
}
pub(super) fn nonce(path: &str) -> Result<[u8; 32]> {
    let hex = path.strip_prefix("/time/").ok_or("time relay path")?;
    if hex.len() != 64 {
        return Err("time relay nonce length".into());
    }
    let mut bytes = [0; 32];
    for (out, pair) in bytes.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let digit = |b| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err("time relay noncanonical nonce".to_string()),
        };
        *out = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_udp_request_has_exact_nonce_and_reply_is_only_untrusted_bytes() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut relay = Relay::new(server.local_addr().unwrap());
        let responder = std::thread::spawn(move || {
            let mut received = [0; 1025];
            let (n, peer) = server.recv_from(&mut received).unwrap();
            let mut expected = [0; 1024];
            ev_time_proof::encode_relay_request(&[0xab; 32], &mut expected);
            assert_eq!(&received[..n], expected);
            server
                .send_to(b"not a signed time assertion", peer)
                .unwrap();
        });
        let stop = AtomicBool::new(false);
        assert_eq!(
            relay
                .query(&[0xab; 32], Instant::now() + Duration::from_secs(2), &stop)
                .unwrap(),
            b"not a signed time assertion"
        );
        assert!(
            relay
                .query(&[1; 32], Instant::now() + Duration::from_secs(2), &stop)
                .is_err()
        );
        responder.join().unwrap();
    }
    #[test]
    fn oversized_datagram_original_deadline_and_noncanonical_nonce_refuse() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut relay = Relay::new(server.local_addr().unwrap());
        let responder = std::thread::spawn(move || {
            let (_, peer) = server.recv_from(&mut [0; 1024]).unwrap();
            server
                .send_to(&[7; ev_time_proof::MAX_REPLY_BYTES + 32], peer)
                .unwrap();
        });
        let stop = AtomicBool::new(false);
        assert!(relay.query(&[1; 32], Instant::now(), &stop).is_err());
        assert!(relay.last_query.is_none());
        assert!(
            relay
                .query(&[1; 32], Instant::now() + Duration::from_secs(2), &stop)
                .is_err()
        );
        responder.join().unwrap();
        assert_eq!(
            nonce(&format!("/time/{}", "ab".repeat(32))).unwrap(),
            [0xab; 32]
        );
        for path in [
            format!("/time/{}", "AB".repeat(32)),
            format!("/time/{}", "g0".repeat(32)),
            format!("/time/{}", "a".repeat(63)),
            format!("/other/{}", "00".repeat(32)),
        ] {
            assert!(nonce(&path).is_err());
        }
    }
}
