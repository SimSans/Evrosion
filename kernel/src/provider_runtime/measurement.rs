//! Optional generic capture adapter for one authenticated Root-owned batch.
//! Counts/route are mechanism observations; no benchmark count or answer formula
//! is present here. Source actors and host acceptance choose their own workload.
use super::{CompletedCall, Identity};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub endpoint: u64,
    pub send_handle: u64,
    pub caller: Identity,
    pub callee: Identity,
}
impl Route {
    fn from_call(c: &CompletedCall) -> Self {
        Self {
            endpoint: c.endpoint,
            send_handle: c.send_handle,
            caller: c.caller,
            callee: c.callee,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub phase: u8,
    pub tick: u64,
    pub calls: u64,
    pub replies: u64,
    pub rejected: u64,
    pub completed: u64,
    pub first_nonce: u64,
    pub last_nonce: u64,
    pub route: Option<Route>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Ready,
    Snapshot(Snapshot),
    Sample([u64; 4]),
    Finish,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Sequence,
    Route,
    Nonce,
    Overflow,
    Pending,
}
#[derive(Clone, Copy)]
enum Stage {
    New,
    Ready,
    Before,
    After,
    Words(usize),
    End,
    Sample,
    Finished,
}
pub struct Recorder {
    stage: Stage,
    route: Option<Route>,
    first_nonce: u64,
    last_nonce: u64,
    completed: u64,
    words: [u64; 4],
}
impl Recorder {
    pub const fn new() -> Self {
        Self {
            stage: Stage::New,
            route: None,
            first_nonce: 0,
            last_nonce: 0,
            completed: 0,
            words: [0; 4],
        }
    }
    pub fn complete(&mut self, c: &CompletedCall) -> Result<(), Error> {
        let _opaque_payload = (c.request, c.reply);
        let route = Route::from_call(c);
        if self.route.is_some_and(|old| old != route) {
            return Err(Error::Route);
        }
        if c.nonce == 0 || c.nonce <= self.last_nonce {
            return Err(Error::Nonce);
        }
        if self.completed == 0 {
            self.first_nonce = c.nonce;
        }
        self.completed = self.completed.checked_add(1).ok_or(Error::Overflow)?;
        self.last_nonce = c.nonce;
        self.route = Some(route);
        Ok(())
    }
    /// Caller authenticates Root sender through ordinary protected receive.
    /// `pending`/counts/tick come from retained actual owners, never packet IDs.
    pub fn push(
        &mut self,
        body: [u8; 8],
        tick: u64,
        calls: u64,
        replies: u64,
        rejected: u64,
        pending: bool,
    ) -> Result<Option<Event>, Error> {
        let tag = |code| body == [b'I', b'B', 1, code, 0, 0, 0, 0];
        match self.stage {
            Stage::New if body == ev_userspace_contract::Event::Ready.encode() => {
                self.stage = Stage::Ready;
                Ok(Some(Event::Ready))
            }
            Stage::Ready if tag(7) => {
                if pending {
                    return Err(Error::Pending);
                }
                self.stage = Stage::Before;
                Ok(Some(Event::Snapshot(
                    self.snapshot(1, tick, calls, replies, rejected),
                )))
            }
            Stage::Before if tag(8) => {
                if pending {
                    return Err(Error::Pending);
                }
                self.stage = Stage::After;
                Ok(Some(Event::Snapshot(
                    self.snapshot(2, tick, calls, replies, rejected),
                )))
            }
            Stage::After if tag(5) => {
                self.stage = Stage::Words(0);
                Ok(None)
            }
            Stage::Words(i) => {
                self.words[i] = u64::from_le_bytes(body);
                self.stage = if i == 3 {
                    Stage::End
                } else {
                    Stage::Words(i + 1)
                };
                Ok(None)
            }
            Stage::End if tag(6) => {
                self.stage = Stage::Sample;
                Ok(Some(Event::Sample(self.words)))
            }
            Stage::Sample if tag(9) => {
                self.stage = Stage::Finished;
                Ok(Some(Event::Finish))
            }
            _ => Err(Error::Sequence),
        }
    }
    fn snapshot(&self, phase: u8, tick: u64, calls: u64, replies: u64, rejected: u64) -> Snapshot {
        Snapshot {
            phase,
            tick,
            calls,
            replies,
            rejected,
            completed: self.completed,
            first_nonce: self.first_nonce,
            last_nonce: self.last_nonce,
            route: self.route,
        }
    }
    pub fn finished(&self) -> bool {
        matches!(self.stage, Stage::Finished)
    }
}
impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn tag(n: u8) -> [u8; 8] {
        [b'I', b'B', 1, n, 0, 0, 0, 0]
    }
    #[test]
    fn observed_route_and_nonces_never_follow_a_rebound_or_replayed_call() {
        let id = |n| Identity {
            process: n,
            thread: n + 10,
            image_sha256: [n as u8; 32],
        };
        let mut call = CompletedCall {
            nonce: 1,
            endpoint: 7,
            send_handle: 513,
            caller: id(2),
            callee: id(3),
            request: 0x45,
            reply: 0x89,
        };
        let mut r = Recorder::new();
        r.complete(&call).unwrap();
        assert_eq!(r.complete(&call), Err(Error::Nonce));
        call.nonce = 2;
        call.send_handle = 514;
        assert_eq!(r.complete(&call), Err(Error::Route));
        call.send_handle = 513;
        call.callee = id(4);
        assert_eq!(r.complete(&call), Err(Error::Route));
    }
    #[test]
    fn incomplete_replayed_mixed_and_inflight_batches_refuse() {
        let mut r = Recorder::new();
        assert_eq!(r.push(tag(7), 0, 0, 0, 0, false), Err(Error::Sequence));
        r.push(
            ev_userspace_contract::Event::Ready.encode(),
            0,
            0,
            0,
            0,
            false,
        )
        .unwrap();
        assert_eq!(r.push(tag(7), 0, 1, 0, 0, true), Err(Error::Pending));
        r.push(tag(7), 1, 1, 1, 0, false).unwrap();
        assert_eq!(r.push(tag(7), 1, 1, 1, 0, false), Err(Error::Sequence));
        r.push(tag(8), 2, 2, 2, 0, false).unwrap();
        r.push(tag(5), 2, 2, 2, 0, false).unwrap();
        for word in [3u64, 4, 5, 6] {
            r.push(word.to_le_bytes(), 2, 2, 2, 0, false).unwrap();
        }
        assert_eq!(
            r.push(tag(6), 2, 2, 2, 0, false),
            Ok(Some(Event::Sample([3, 4, 5, 6])))
        );
        assert!(!r.finished());
        r.push(tag(9), 2, 2, 2, 0, false).unwrap();
        assert!(r.finished());
        assert_eq!(r.push(tag(9), 2, 2, 2, 0, false), Err(Error::Sequence));
    }
}
