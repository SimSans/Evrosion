//! Closed physical File/Object fixture diagnostics. IDs/counts here are not
//! authority; the kernel independently checks actual routes, waits and copying.
pub const BYTES: usize = 512;
pub const COMPLETION_BYTES: usize = 256;
pub const DATA_A: &[u8] = b"file-content-A";
pub const DATA_B: &[u8] = b"file-content-B";
pub const CALL: [u8; 8] = *b"EVF1CALL";
pub const REPLY: [u8; 8] = *b"EVF1DONE";
pub const READY: [u8; 8] = *b"EVFREADY";
pub const EARLY: [u8; 8] = *b"EVFEARLY";
pub const COPY_TAG: u64 = 0x464c5350;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Write = 0,
    Verify = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Magic,
    Version,
    Mode,
    Reserved,
    Layout,
    Completion,
}
fn mode(value: u8) -> Result<Mode, Error> {
    match value {
        0 => Ok(Mode::Write),
        1 => Ok(Mode::Verify),
        _ => Err(Error::Mode),
    }
}
fn wide(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    pub mode: Mode,
}
impl Control {
    pub const fn new(mode: Mode) -> Self {
        Self { mode }
    }
    pub fn encode(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..4].copy_from_slice(b"EVFT");
        bytes[4] = 1;
        bytes[5] = self.mode as u8;
        bytes[16..20].copy_from_slice(&16u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&14u32.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES {
            return Err(Error::Length);
        }
        if &bytes[..4] != b"EVFT" {
            return Err(Error::Magic);
        }
        if bytes[4] != 1 {
            return Err(Error::Version);
        }
        if bytes[6..16].iter().chain(&bytes[24..]).any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        if bytes[16..20] != 16u32.to_le_bytes() || bytes[20..24] != 14u32.to_le_bytes() {
            return Err(Error::Layout);
        }
        Ok(Self {
            mode: mode(bytes[5])?,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub mode: Mode,
    pub object: u64,
    pub counter: u64,
    pub requests: u64,
    pub ro_denied: u64,
    pub malformed: u64,
    pub invalid_counter: u64,
    pub skipped: u64,
    pub conflicting: u64,
    pub duplicates: u64,
    pub port_denied: u64,
    pub block_denied: u64,
    pub private_snapshot: u64,
    pub payload: [u8; 32],
}
impl Completion {
    pub fn encode(self) -> [u8; COMPLETION_BYTES] {
        let mut bytes = [0; COMPLETION_BYTES];
        bytes[..4].copy_from_slice(b"EVFC");
        bytes[4] = 1;
        bytes[5] = self.mode as u8;
        bytes[6] = 1;
        for (i, value) in [
            self.object,
            self.counter,
            self.requests,
            self.ro_denied,
            self.malformed,
            self.invalid_counter,
            self.skipped,
            self.conflicting,
            self.duplicates,
            self.port_denied,
            self.block_denied,
            self.private_snapshot,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[8 + i * 8..16 + i * 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[104..136].copy_from_slice(&self.payload);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != COMPLETION_BYTES {
            return Err(Error::Length);
        }
        if &bytes[..4] != b"EVFC" {
            return Err(Error::Magic);
        }
        if bytes[4] != 1 {
            return Err(Error::Version);
        }
        if bytes[6] != 1 || bytes[7] != 0 || bytes[136..].iter().any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        let mut payload = [0; 32];
        payload.copy_from_slice(&bytes[104..136]);
        let result = Self {
            mode: mode(bytes[5])?,
            object: wide(bytes, 8),
            counter: wide(bytes, 16),
            requests: wide(bytes, 24),
            ro_denied: wide(bytes, 32),
            malformed: wide(bytes, 40),
            invalid_counter: wide(bytes, 48),
            skipped: wide(bytes, 56),
            conflicting: wide(bytes, 64),
            duplicates: wide(bytes, 72),
            port_denied: wide(bytes, 80),
            block_denied: wide(bytes, 88),
            private_snapshot: wide(bytes, 96),
            payload,
        };
        let write = result.mode == Mode::Write;
        if result.object != 1
            || result.counter != 1
            || result.requests != if write { 11 } else { 7 }
            || result.ro_denied != 1
            || result.malformed != 2
            || result.invalid_counter != 2
            || result.skipped != u64::from(write)
            || result.conflicting != u64::from(write)
            || result.duplicates != u64::from(write)
            || result.port_denied != 1
            || result.block_denied != 1
            || result.private_snapshot != u64::from(write)
            || result.payload == [0; 32]
        {
            return Err(Error::Completion);
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_total_canonical_modes_and_no_client_global_selector() {
        for mode in [Mode::Write, Mode::Verify] {
            let control = Control::new(mode);
            let bytes = control.encode();
            assert_eq!(Control::decode(&bytes), Ok(control));
            for length in 0..BYTES {
                assert_eq!(Control::decode(&bytes[..length]), Err(Error::Length));
            }
            for offset in (6..16).chain(24..BYTES) {
                let mut bad = bytes;
                bad[offset] = 1;
                assert!(Control::decode(&bad).is_err());
            }
            for value in 2..=255 {
                let mut bad = bytes;
                bad[5] = value;
                assert_eq!(Control::decode(&bad), Err(Error::Mode));
            }
        }
    }
    #[test]
    fn completion_requires_actual_phase_specific_counts_and_canonical_tail() {
        for mode in [Mode::Write, Mode::Verify] {
            let write = mode == Mode::Write;
            let c = Completion {
                mode,
                object: 1,
                counter: 1,
                requests: if write { 11 } else { 7 },
                ro_denied: 1,
                malformed: 2,
                invalid_counter: 2,
                skipped: u64::from(write),
                conflicting: u64::from(write),
                duplicates: u64::from(write),
                port_denied: 1,
                block_denied: 1,
                private_snapshot: u64::from(write),
                payload: [7; 32],
            };
            let bytes = c.encode();
            assert_eq!(Completion::decode(&bytes), Ok(c));
            for length in 0..COMPLETION_BYTES {
                assert_eq!(Completion::decode(&bytes[..length]), Err(Error::Length));
            }
            for offset in [6, 7, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96]
                .into_iter()
                .chain(136..COMPLETION_BYTES)
            {
                let mut bad = bytes;
                bad[offset] ^= 8;
                assert!(Completion::decode(&bad).is_err());
            }
        }
    }
}
