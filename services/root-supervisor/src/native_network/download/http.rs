//! Incremental bounded framing; body is copied directly into the caller's
//! reusable private chunk, never accumulated as a full artifact here.
use super::{CHUNK_BYTES, Error, Expectation};
pub(super) struct Http {
    line: [u8; 128],
    used: usize,
    total: usize,
    status: bool,
    headers: bool,
    length: Option<u64>,
    received: u64,
    content_type: bool,
    connection: bool,
}
impl Http {
    pub(super) const fn new() -> Self {
        Self {
            line: [0; 128],
            used: 0,
            total: 0,
            status: false,
            headers: false,
            length: None,
            received: 0,
            content_type: false,
            connection: false,
        }
    }
    pub(super) fn length(&self) -> Option<u64> {
        if self.headers { self.length } else { None }
    }
    pub(super) fn received(&self) -> u64 {
        self.received
    }
    pub(super) fn finish(&self) -> Result<(), Error> {
        if self.headers && self.length == Some(self.received) {
            Ok(())
        } else {
            Err(Error::Http)
        }
    }
    pub(super) fn push(
        &mut self,
        bytes: &[u8],
        maximum: u64,
        expected: Expectation,
        chunk: &mut [u8; CHUNK_BYTES],
        used: &mut usize,
    ) -> Result<(), Error> {
        for &byte in bytes {
            if self.headers {
                if self.received >= self.length.ok_or(Error::Http)? || *used >= CHUNK_BYTES {
                    return Err(Error::Length);
                }
                chunk[*used] = byte;
                *used += 1;
                self.received = self.received.checked_add(1).ok_or(Error::Length)?;
                continue;
            }
            self.total = self
                .total
                .checked_add(1)
                .filter(|n| *n <= 512)
                .ok_or(Error::Http)?;
            if byte == b'\n' {
                if self.used == 0 || self.line[self.used - 1] != b'\r' {
                    return Err(Error::Http);
                }
                let line = &self.line[..self.used - 1];
                if line.iter().any(|b| matches!(*b, b'\r' | b'\n')) {
                    return Err(Error::Http);
                }
                if !self.status {
                    if line != b"HTTP/1.1 200 OK" {
                        return Err(Error::Http);
                    }
                    self.status = true;
                } else if line.is_empty() {
                    let length = self.length.ok_or(Error::Http)?;
                    if !self.connection || length == 0 || length > maximum {
                        return Err(Error::Length);
                    }
                    if let Expectation::Exact {
                        length: expected, ..
                    } = expected
                        && length != expected
                    {
                        return Err(Error::Length);
                    }
                    self.headers = true;
                } else {
                    let colon = line
                        .iter()
                        .position(|b| *b == b':')
                        .filter(|n| *n != 0)
                        .ok_or(Error::Http)?;
                    let name = &line[..colon];
                    let value = line[colon + 1..].strip_prefix(b" ").ok_or(Error::Http)?;
                    if name.eq_ignore_ascii_case(b"Content-Length") {
                        if self.length.is_some() || value.is_empty() || value[0] == b'0' {
                            return Err(Error::Http);
                        }
                        let mut length = 0u64;
                        for &b in value {
                            if !b.is_ascii_digit() {
                                return Err(Error::Http);
                            }
                            length = length
                                .checked_mul(10)
                                .and_then(|n| n.checked_add(u64::from(b - b'0')))
                                .filter(|n| *n <= maximum)
                                .ok_or(Error::Length)?;
                        }
                        self.length = Some(length);
                    } else if name.eq_ignore_ascii_case(b"Content-Type") {
                        if self.content_type || value != b"application/octet-stream" {
                            return Err(Error::Http);
                        }
                        self.content_type = true;
                    } else if name.eq_ignore_ascii_case(b"Connection") {
                        if self.connection || !value.eq_ignore_ascii_case(b"close") {
                            return Err(Error::Http);
                        }
                        self.connection = true;
                    } else {
                        return Err(Error::Http);
                    }
                }
                self.used = 0;
            } else {
                if self.used == self.line.len()
                    || !(byte.is_ascii_graphic() || matches!(byte, b' ' | b'\r'))
                {
                    return Err(Error::Http);
                }
                self.line[self.used] = byte;
                self.used += 1;
            }
        }
        Ok(())
    }
}
