//! Complete explicit owner-UART response parser, NOT authentication or a fake
//! protected Picker/Input receipt. Actual adapter must display canonical action,
//! drain pre-prompt input, arm only after real UART output and bound its expiry.
use ev_picker::{AppId, Consent, Origin, UserId};
use sha2::{Digest as _, Sha256};

pub const MAX_LINE: usize = 72;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Inactive,
    Invalid,
    Incomplete,
    Expired,
    Clock,
    Exhausted,
}
/// Canonical revocation action is distinct from a remembered READ approval.
/// Actual SourceRoot resolves these fields from its latest authoritative head;
/// constructing this hash never authenticates an owner or retires a live cap.
pub fn revoke_action(
    user: UserId,
    app: AppId,
    grant_serial: u64,
    revision: u64,
    record_digest: [u8; 32],
) -> Result<[u8; 32], Error> {
    if [grant_serial, revision]
        .into_iter()
        .any(|n| n == 0 || n == u64::MAX)
        || record_digest == [0; 32]
    {
        return Err(Error::Exhausted);
    }
    let mut h = Sha256::new();
    h.update(b"evrosion.native.explicit-owner-revoke-read.v1\0");
    h.update(user.bytes());
    h.update(app.bytes());
    h.update(grant_serial.to_le_bytes());
    h.update(revision.to_le_bytes());
    h.update(record_digest);
    Ok(h.finalize().into())
}
pub struct Gate {
    token: [u8; 64],
    action: [u8; 32],
    owner: UserId,
    displayed: u64,
    expiry: u64,
    line: [u8; MAX_LINE],
    length: usize,
    invalid: bool,
    armed: bool,
    active: bool,
}
impl Gate {
    /// Correlation token is public metadata, not a bearer permission. Actual
    /// trusted owner channel/input ordering, not knowing this hash, is consent.
    pub fn prepare(action: [u8; 32], owner: UserId, prompt_serial: u64) -> Result<Self, Error> {
        if prompt_serial == 0 || prompt_serial == u64::MAX || action == [0; 32] {
            return Err(Error::Exhausted);
        }
        let mut hash = Sha256::new();
        hash.update(b"evrosion.native.explicit-owner-policy-action.v1\0");
        hash.update(action);
        hash.update(prompt_serial.to_le_bytes());
        let sum: [u8; 32] = hash.finalize().into();
        let mut token = [0; 64];
        for (i, value) in sum.into_iter().enumerate() {
            token[2 * i] = b"0123456789abcdef"[(value >> 4) as usize];
            token[2 * i + 1] = b"0123456789abcdef"[(value & 15) as usize];
        }
        Ok(Self {
            token,
            action,
            owner,
            displayed: 0,
            expiry: 0,
            line: [0; MAX_LINE],
            length: 0,
            invalid: false,
            armed: false,
            active: false,
        })
    }
    pub const fn token(&self) -> &[u8; 64] {
        &self.token
    }
    /// Call only after actual UART prompt output and bounded pre-approval input
    /// drain. This method is an integration boundary, not proof of those facts.
    pub fn arm_after_actual_prompt(&mut self, displayed: u64, expiry: u64) -> Result<(), Error> {
        if self.armed {
            return Err(Error::Inactive);
        }
        if displayed == 0 || displayed >= expiry || expiry == u64::MAX {
            return Err(Error::Expired);
        }
        self.displayed = displayed;
        self.expiry = expiry;
        self.armed = true;
        self.active = true;
        Ok(())
    }
    pub fn byte(&mut self, byte: u8, now: u64) -> Result<Option<Consent>, Error> {
        if !self.active {
            return Err(Error::Inactive);
        }
        if now < self.displayed {
            self.active = false;
            return Err(Error::Clock);
        }
        if now >= self.expiry {
            self.active = false;
            return Err(Error::Expired);
        }
        if byte == b'\r' || byte == b'\n' {
            self.active = false;
            if self.invalid
                || self.length != MAX_LINE
                || &self.line[..8] != b"approve "
                || self.line[8..] != self.token
            {
                return Err(Error::Invalid);
            }
            return Ok(Some(Consent {
                displayed_action: self.action,
                approver: self.owner,
                origin: Origin::ExplicitOwnerAction,
            }));
        }
        if !(b' '..=b'~').contains(&byte) || self.length == MAX_LINE {
            self.invalid = true;
        } else {
            self.line[self.length] = byte;
            self.length += 1;
        }
        Ok(None)
    }
    pub fn end_of_input(&mut self) -> Result<(), Error> {
        self.active = false;
        Err(Error::Incomplete)
    }
}
