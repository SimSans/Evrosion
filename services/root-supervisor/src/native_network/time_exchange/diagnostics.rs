//! Bounded factual TP retention. It creates no time/transport authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub bytes: [u8; 8],
    pub cut: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Frame,
    Clock,
    Capacity,
    Overflow,
}
pub struct Diagnostics {
    entries: [Option<Entry>; 4],
    head: usize,
    len: usize,
    total: u8,
    last: u64,
}
impl Default for Diagnostics {
    fn default() -> Self {
        Self::new()
    }
}
impl Diagnostics {
    pub const fn new() -> Self {
        Self {
            entries: [None; 4],
            head: 0,
            len: 0,
            total: 0,
            last: 0,
        }
    }
    pub fn pending(&self) -> bool {
        self.len != 0
    }
    pub fn push(&mut self, stage: u8, result: u8, arg: u32, now: u64) -> Result<(), Error> {
        let valid = match stage {
            1 => result == 0 && arg != 0 && arg != u32::MAX,
            2 => result == 0 && (1..=864).contains(&arg),
            3 => result == 0 && arg == 11,
            4 => (1..=5).contains(&result) && (1..=3).contains(&arg),
            _ => false,
        };
        if !valid {
            return Err(Error::Frame);
        }
        if now < self.last {
            return Err(Error::Clock);
        }
        if self.total == 4 || self.len == 4 {
            return Err(Error::Capacity);
        }
        let cut = now
            .checked_add(4096)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Overflow)?;
        let mut bytes = [b'T', b'P', stage, result, 0, 0, 0, 0];
        bytes[4..].copy_from_slice(&arg.to_le_bytes());
        let at = (self.head + self.len) % 4;
        self.entries[at] = Some(Entry { bytes, cut });
        self.len += 1;
        self.total += 1;
        self.last = now;
        Ok(())
    }
    /// Expired unaccepted diagnostics retire, never become successful events.
    /// Busy callers retain the exact front Entry and its original cut.
    pub fn front(&mut self, now: u64) -> Option<Entry> {
        if now < self.last || now == u64::MAX {
            // These frames are all unaccepted; losing a diagnostic must not
            // create a perpetual finish debt or a fabricated success record.
            while self.len != 0 {
                self.retire();
            }
            return None;
        }
        self.last = now;
        while self.len != 0 {
            let e = self.entries[self.head].unwrap();
            if now < e.cut {
                return Some(e);
            }
            self.retire();
        }
        None
    }
    pub fn retire(&mut self) {
        if self.len != 0 {
            self.entries[self.head] = None;
            self.head = (self.head + 1) % 4;
            self.len -= 1;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn received_and_verified_same_tick_keep_distinct_immutable_fifo_frames() {
        let mut q = Diagnostics::new();
        q.push(1, 0, 1, 10).unwrap();
        q.push(2, 0, 352, 20).unwrap();
        q.push(3, 0, 11, 20).unwrap();
        let first = q.front(20).unwrap();
        assert_eq!(first.cut, 4106);
        for tick in [21, 22, 50, 100] {
            assert_eq!(q.front(tick), Some(first));
        } //Busy never retires
        q.retire();
        let second = q.front(100).unwrap();
        assert_eq!(second.cut, 4116);
        assert_eq!(second.bytes[2], 2);
        q.retire();
        assert_eq!(q.front(100).unwrap().bytes[2], 3);
        q.retire();
        assert!(!q.pending());
    }
    #[test]
    fn lifetime_cap_refuses_overwrite_and_exact_cut_is_expired_without_success() {
        let mut q = Diagnostics::new();
        for i in 1..=4 {
            q.push(1, 0, i, i as u64).unwrap();
        }
        assert!(q.push(1, 0, 5, 5).is_err());
        let first = q.front(4096).unwrap();
        assert_eq!(first.bytes[4], 1);
        assert_eq!(q.front(4097).unwrap().bytes[4], 2);
        q.retire();
        q.retire();
        q.retire();
        assert!(!q.pending());
        assert!(q.push(1, 0, 6, 5000).is_err());
        let mut q = Diagnostics::new();
        for (s, r, a) in [
            (0, 0, 1),
            (1, 0, 0),
            (2, 0, 865),
            (3, 0, 1),
            (3, 1, 11),
            (4, 0, 1),
            (4, 6, 1),
            (4, 1, 4),
        ] {
            assert!(q.push(s, r, a, 1).is_err());
            assert!(!q.pending());
        }
        assert!(q.push(1, 0, 1, u64::MAX - 4095).is_err());
        assert!(!q.pending());
        let mut q = Diagnostics::new();
        q.push(1, 0, 1, 10).unwrap();
        assert_eq!(q.front(9), None);
        assert!(!q.pending());
        assert_eq!(q.push(4, 1, 1, 9), Err(Error::Clock));
    }
}
