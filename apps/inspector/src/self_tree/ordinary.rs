//! Finite ordinary-control custody while actual own Present remains held.
//! Scope is supplied by the last complete accepted self-tree, never a packet.
use ev_userspace_contract::root_v5::assistive::{Intent, IntentKind};
use ev_workspace_client::semantic as a1;

fn nonce(value: u32) -> bool {
    !matches!(value, 0 | u32::MAX)
}
fn code(control: u16) -> Option<u8> {
    match control {
        201..=218 if control != 213 => Some((control - 200) as u8),
        300..=315 => Some((control - 300 + 32) as u8),
        _ => None,
    }
}
fn control(code: u8) -> Option<u16> {
    match code {
        1..=18 if code != 13 => Some(u16::from(code) + 200),
        32..=47 => Some(u16::from(code) - 32 + 300),
        _ => None,
    }
}
fn kind(value: u8) -> Option<IntentKind> {
    if !matches!(value, 1..=18) || value == 13 {
        return None;
    }
    let field = 0x8300u16 + (u16::from(value) << 4);
    let f = field.to_le_bytes();
    Intent::decode([b'A', 1, f[0], f[1], 1, 0, 0, 0])
        .ok()
        .map(|intent| intent.kind)
}
fn expected(control: u16) -> Option<IntentKind> {
    Some(match control {
        201 => IntentKind::PreviousNode,
        202 => IntentKind::NextNode,
        203 | 300..=315 => IntentKind::AssistiveFocus,
        204 => IntentKind::Activate,
        205 => IntentKind::KeyboardFocus,
        206 => IntentKind::Expand,
        207 => IntentKind::ReadLabel,
        208 => IntentKind::ReadDocument,
        209 => IntentKind::Refresh,
        210 => IntentKind::PreviousSource,
        211 => IntentKind::NextSource,
        212 => IntentKind::Disable,
        214 => IntentKind::Cancel,
        215 => IntentKind::Select,
        216 => IntentKind::ScrollUp,
        217 => IntentKind::ScrollDown,
        218 => IntentKind::MoreText,
        _ => return None,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Begin { nonce: u32, control: u16 },
    CutLow { word: u32 },
    CutHigh { word: u32 },
    Commit { nonce: u32 },
    Acknowledge { nonce: u32 },
}
impl Request {
    pub fn encode(self) -> Result<[u8; 8], a1::Error> {
        let (op, code, word) = match self {
            Self::Begin {
                nonce: n,
                control: c,
            } if nonce(n) => (1, code(c).ok_or(a1::Error::Field)?, n),
            Self::CutLow { word } => (2, 0, word),
            Self::CutHigh { word } => (3, 0, word),
            Self::Commit { nonce: n } if nonce(n) => (4, 0, n),
            Self::Acknowledge { nonce: n } if nonce(n) => (5, 0, n),
            _ => return Err(a1::Error::Nonce),
        };
        let n = word.to_le_bytes();
        Ok([b'I', b'C', op, code, n[0], n[1], n[2], n[3]])
    }
    pub fn decode(bytes: [u8; 8]) -> Result<Self, a1::Error> {
        if bytes[..2] != *b"IC" {
            return Err(a1::Error::Wire);
        }
        let word = u32::from_le_bytes(bytes[4..].try_into().unwrap());
        let request = match (bytes[2], bytes[3]) {
            (1, code) => Self::Begin {
                nonce: word,
                control: control(code).ok_or(a1::Error::Field)?,
            },
            (2, 0) => Self::CutLow { word },
            (3, 0) => Self::CutHigh { word },
            (4, 0) => Self::Commit { nonce: word },
            (5, 0) => Self::Acknowledge { nonce: word },
            _ => return Err(a1::Error::Field),
        };
        if request.encode()? != bytes {
            return Err(a1::Error::Wire);
        }
        Ok(request)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub nonce: u32,
    pub kind: Option<IntentKind>,
    pub index: u8,
}
impl Reply {
    pub fn encode(self) -> Result<[u8; 8], a1::Error> {
        if !nonce(self.nonce) {
            return Err(a1::Error::Nonce);
        }
        let k = match self.kind {
            None if self.index == 0 => 0,
            Some(k) if kind(k as u8) == Some(k) && self.index < 16 => k as u8,
            _ => return Err(a1::Error::Field),
        };
        let n = self.nonce.to_le_bytes();
        Ok([b'I', b'R', k, self.index, n[0], n[1], n[2], n[3]])
    }
    pub fn decode(bytes: [u8; 8]) -> Result<Self, a1::Error> {
        if bytes[..2] != *b"IR" {
            return Err(a1::Error::Wire);
        }
        let value = Self {
            nonce: u32::from_le_bytes(bytes[4..].try_into().unwrap()),
            kind: if bytes[2] == 0 {
                None
            } else {
                Some(kind(bytes[2]).ok_or(a1::Error::Field)?)
            },
            index: bytes[3],
        };
        value.encode()?;
        Ok(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    pub header: a1::Header,
    pub control: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    Low,
    High,
    Commit,
    Executing,
    ReplyPending,
    AwaitAck,
    Blocked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Held {
    scope: Scope,
    ceiling: u64,
    by: u64,
    original: Option<u64>,
    low: Option<u32>,
    reply: Option<[u8; 8]>,
}
pub struct Gate {
    phase: Phase,
    held: Option<Held>,
    last_nonce: u32,
    last_clock: u64,
}
impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}
impl Gate {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            held: None,
            last_nonce: 0,
            last_clock: 0,
        }
    }
    pub const fn holding(&self) -> bool {
        !matches!(self.phase, Phase::Idle)
    }
    pub const fn blocked(&self) -> bool {
        matches!(self.phase, Phase::Blocked)
    }
    pub fn fence(&mut self) {
        self.phase = Phase::Blocked;
    }
    pub fn by(&self) -> Option<u64> {
        self.held.map(|held| held.by)
    }
    pub fn original_cut(&self) -> Option<u64> {
        self.held.and_then(|held| held.original)
    }
    pub fn nonce(&self) -> Option<u32> {
        self.held.map(|held| held.scope.header.nonce)
    }
    pub fn scope(&self) -> Option<Scope> {
        self.held.map(|held| held.scope)
    }
    fn fail<T>(&mut self, error: a1::Error) -> Result<T, a1::Error> {
        self.fence();
        Err(error)
    }
    fn live(&mut self, now: u64) -> Result<(), a1::Error> {
        if self.blocked() {
            return Err(a1::Error::Quarantined);
        }
        if now == u64::MAX || now < self.last_clock || self.held.is_some_and(|held| now >= held.by)
        {
            return self.fail(a1::Error::Value);
        }
        self.last_clock = now;
        Ok(())
    }
    pub fn tick(&mut self, now: u64) {
        let _ = self.live(now);
    }
    pub fn receive(
        &mut self,
        request: Request,
        scope: Option<Scope>,
        now: u64,
        stage_by: u64,
    ) -> Result<Option<u16>, a1::Error> {
        self.live(now)?;
        if let Err(error) = request.encode() {
            return self.fail(error);
        }
        if let Request::Begin { nonce, control } = request {
            if self.phase != Phase::Idle || nonce <= self.last_nonce {
                return self.fail(a1::Error::State);
            }
            let Some(scope) = scope.filter(|scope| {
                scope.header.nonce == nonce
                    && scope.control == control
                    && scope.header.keyboard == control
                    && scope.header.view > 0
                    && scope.header.view < u64::from(u32::MAX)
                    && ![
                        scope.header.model,
                        scope.header.frame,
                        scope.header.mapping_epoch,
                    ]
                    .into_iter()
                    .any(|value| matches!(value, 0 | u64::MAX))
            }) else {
                return self.fail(a1::Error::Value);
            };
            if stage_by <= now || stage_by == u64::MAX {
                return self.fail(a1::Error::Value);
            }
            self.held = Some(Held {
                scope,
                ceiling: stage_by,
                by: stage_by,
                original: None,
                low: None,
                reply: None,
            });
            self.phase = Phase::Low;
            return Ok(None);
        }
        let Some(mut held) = self.held else {
            return self.fail(a1::Error::State);
        };
        if matches!(self.phase, Phase::Low | Phase::High | Phase::Commit)
            && scope != Some(held.scope)
        {
            return self.fail(a1::Error::Value);
        }
        match (self.phase, request) {
            (Phase::Low, Request::CutLow { word }) => {
                held.low = Some(word);
                self.held = Some(held);
                self.phase = Phase::High;
                Ok(None)
            }
            (Phase::High, Request::CutHigh { word }) => {
                let cut = (u64::from(word) << 32) | u64::from(held.low.unwrap());
                held.original = Some(cut);
                held.by = held.ceiling.min(cut);
                self.held = Some(held);
                if matches!(cut, 0 | u64::MAX) || now >= held.by {
                    return self.fail(a1::Error::Value);
                }
                self.phase = Phase::Commit;
                Ok(None)
            }
            (Phase::Commit, Request::Commit { nonce }) if nonce == held.scope.header.nonce => {
                self.phase = Phase::Executing;
                Ok(Some(held.scope.control))
            }
            (Phase::AwaitAck, Request::Acknowledge { nonce })
                if nonce == held.scope.header.nonce =>
            {
                self.last_nonce = nonce;
                self.held = None;
                self.phase = Phase::Idle;
                Ok(None)
            }
            _ => self.fail(a1::Error::Order),
        }
    }
    pub fn record_reply(&mut self, intent: Option<Intent>, now: u64) -> Result<(), a1::Error> {
        self.live(now)?;
        if self.phase != Phase::Executing {
            return self.fail(a1::Error::State);
        }
        let held = self.held.unwrap();
        let (kind, index) = match intent {
            None if matches!(held.scope.control, 201 | 202) => (None, 0),
            Some(intent)
                if u64::from(intent.view) == held.scope.header.view
                    && Some(intent.kind) == expected(held.scope.control)
                    && intent.index < 16
                    && (!(300..=315).contains(&held.scope.control)
                        || u16::from(intent.index) == held.scope.control - 300) =>
            {
                (Some(intent.kind), intent.index)
            }
            _ => return self.fail(a1::Error::Value),
        };
        let reply = Reply {
            nonce: held.scope.header.nonce,
            kind,
            index,
        }
        .encode()
        .inspect_err(|_| self.fence())?;
        self.held.as_mut().unwrap().reply = Some(reply);
        self.phase = Phase::ReplyPending;
        Ok(())
    }
    pub fn next(&self) -> Option<[u8; 8]> {
        if self.phase == Phase::ReplyPending {
            self.held.and_then(|held| held.reply)
        } else {
            None
        }
    }
    /// Call only after actual SEND0 of the exact original RootEvents reply.
    pub fn sent(&mut self, bytes: [u8; 8]) -> Result<(), a1::Error> {
        if self.phase != Phase::ReplyPending || self.held.and_then(|held| held.reply) != Some(bytes)
        {
            return self.fail(a1::Error::State);
        }
        self.phase = Phase::AwaitAck;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope(nonce: u32, control: u16) -> Scope {
        Scope {
            control,
            header: a1::Header {
                nonce,
                page: 0,
                pages: 1,
                model: 2,
                view: 3,
                frame: 4,
                mapping_epoch: 5,
                width: 320,
                height: 180,
                keyboard: control,
                modal: 0,
            },
        }
    }
    fn staged(control: u16) -> Gate {
        let mut gate = Gate::new();
        let s = Some(scope(7, control));
        assert_eq!(
            gate.receive(Request::Begin { nonce: 7, control }, s, 10, 100),
            Ok(None)
        );
        assert_eq!(
            gate.receive(Request::CutLow { word: 80 }, s, 11, 999),
            Ok(None)
        );
        assert_eq!(
            gate.receive(Request::CutHigh { word: 0 }, s, 12, 999),
            Ok(None)
        );
        gate
    }
    fn executing(control: u16) -> Gate {
        let mut gate = staged(control);
        assert_eq!(
            gate.receive(
                Request::Commit { nonce: 7 },
                Some(scope(7, control)),
                13,
                999
            ),
            Ok(Some(control))
        );
        gate
    }
    #[test]
    fn codecs_are_closed_and_never_encode_protected_confirmation_or_enable() {
        for control in (201..=218).filter(|n| *n != 213).chain(300..=315) {
            let request = Request::Begin { nonce: 7, control };
            assert_eq!(Request::decode(request.encode().unwrap()), Ok(request));
        }
        for control in [0, 200, 213, 219, 299, 316, 9000, 9001] {
            assert!(Request::Begin { nonce: 7, control }.encode().is_err());
        }
        for n in [0, u32::MAX] {
            assert!(Request::Commit { nonce: n }.encode().is_err());
            assert!(
                Reply {
                    nonce: n,
                    kind: None,
                    index: 0
                }
                .encode()
                .is_err()
            );
        }
        for k in [IntentKind::Enable, IntentKind::ConfirmProtected] {
            assert!(
                Reply {
                    nonce: 7,
                    kind: Some(k),
                    index: 0
                }
                .encode()
                .is_err()
            );
        }
        let reply = Reply {
            nonce: 7,
            kind: Some(IntentKind::ReadLabel),
            index: 15,
        };
        assert_eq!(Reply::decode(reply.encode().unwrap()), Ok(reply));
        for bytes in [
            [b'I', b'C', 4, 1, 7, 0, 0, 0],
            [b'I', b'C', 1, 13, 7, 0, 0, 0],
            [b'I', b'R', 0, 1, 7, 0, 0, 0],
            [b'I', b'R', 13, 0, 7, 0, 0, 0],
            [b'I', b'R', 1, 16, 7, 0, 0, 0],
        ] {
            assert!(Request::decode(bytes).is_err());
            assert!(Reply::decode(bytes).is_err());
        }
    }
    #[test]
    fn reply_send_and_ack_hold_present_through_legitimate_post_action_scope_change() {
        let mut gate = executing(207);
        assert!(gate.holding());
        assert_eq!(gate.by(), Some(80));
        assert_eq!(gate.original_cut(), Some(80));
        gate.record_reply(
            Some(Intent {
                kind: IntentKind::ReadLabel,
                index: 2,
                view: 3,
            }),
            14,
        )
        .unwrap();
        let bytes = gate.next().unwrap();
        assert_eq!(gate.next(), Some(bytes));
        assert!(gate.holding());
        gate.sent(bytes).unwrap();
        assert!(gate.holding());
        assert_eq!(gate.next(), None);
        assert_eq!(
            gate.receive(Request::Acknowledge { nonce: 7 }, None, 15, u64::MAX),
            Ok(None)
        );
        assert!(!gate.holding());
        assert!(!gate.blocked());
        let newer = scope(8, 207);
        gate.receive(
            Request::Begin {
                nonce: 8,
                control: 207,
            },
            Some(newer),
            16,
            50,
        )
        .unwrap();
        assert!(
            gate.receive(Request::Acknowledge { nonce: 7 }, None, 17, 1000)
                .is_err()
        );
        assert!(gate.blocked());
        assert_eq!(gate.nonce(), Some(8));
        assert_eq!(gate.by(), Some(50));
    }
    #[test]
    fn stage_ceiling_and_original_cut_never_renew_and_expiry_keeps_exact_slot() {
        let mut gate = Gate::new();
        let s = Some(scope(7, 207));
        gate.receive(
            Request::Begin {
                nonce: 7,
                control: 207,
            },
            s,
            10,
            40,
        )
        .unwrap();
        gate.receive(Request::CutLow { word: 80 }, s, 11, 9999)
            .unwrap();
        gate.receive(Request::CutHigh { word: 0 }, s, 12, 9999)
            .unwrap();
        assert_eq!(gate.original_cut(), Some(80));
        assert_eq!(gate.by(), Some(40));
        gate.tick(40);
        assert!(gate.blocked());
        assert_eq!(gate.scope(), s);
        assert_eq!(gate.by(), Some(40));
        assert!(
            gate.receive(
                Request::Begin {
                    nonce: 8,
                    control: 207
                },
                Some(scope(8, 207)),
                41,
                9999
            )
            .is_err()
        );
        assert_eq!(gate.nonce(), Some(7));
    }
    #[test]
    fn malformed_order_scope_change_early_ack_and_clock_rollback_are_sticky() {
        for mutation in 0..4 {
            let mut gate = staged(207);
            let s = Some(scope(7, 207));
            let result = match mutation {
                0 => gate.receive(Request::CutHigh { word: 0 }, s, 13, 999),
                1 => {
                    let mut changed = scope(7, 207);
                    changed.header.frame += 1;
                    gate.receive(Request::Commit { nonce: 7 }, Some(changed), 13, 999)
                }
                2 => gate.receive(Request::Acknowledge { nonce: 7 }, s, 13, 999),
                _ => gate.receive(Request::Commit { nonce: 7 }, s, 9, 999),
            };
            assert!(result.is_err());
            assert!(gate.blocked());
            assert_eq!(gate.nonce(), Some(7));
            assert_eq!(gate.original_cut(), Some(80));
        }
    }
    #[test]
    fn wrong_reply_kind_view_row_or_none_cannot_escape_original_control() {
        for intent in [
            None,
            Some(Intent {
                kind: IntentKind::Enable,
                index: 0,
                view: 3,
            }),
            Some(Intent {
                kind: IntentKind::ConfirmProtected,
                index: 0,
                view: 3,
            }),
            Some(Intent {
                kind: IntentKind::ReadLabel,
                index: 0,
                view: 4,
            }),
            Some(Intent {
                kind: IntentKind::NextSource,
                index: 0,
                view: 3,
            }),
        ] {
            let mut gate = executing(207);
            assert!(gate.record_reply(intent, 14).is_err());
            assert!(gate.blocked());
            assert!(gate.holding());
            assert_eq!(gate.next(), None);
        }
        let mut gate = executing(301);
        assert!(
            gate.record_reply(
                Some(Intent {
                    kind: IntentKind::AssistiveFocus,
                    index: 0,
                    view: 3
                }),
                14
            )
            .is_err()
        );
        for control in [201, 202] {
            let mut gate = executing(control);
            gate.record_reply(None, 14).unwrap();
            assert_eq!(Reply::decode(gate.next().unwrap()).unwrap().kind, None);
        }
    }
    #[test]
    fn wrong_send_and_late_or_duplicate_ack_never_release_reply_or_new_action() {
        let mut gate = executing(201);
        gate.record_reply(None, 14).unwrap();
        let exact = gate.next().unwrap();
        let mut wrong = exact;
        wrong[7] ^= 1;
        assert!(gate.sent(wrong).is_err());
        assert_eq!(gate.scope(), Some(scope(7, 201)));
        assert!(gate.blocked());
        let mut gate = executing(201);
        gate.record_reply(None, 14).unwrap();
        gate.sent(gate.next().unwrap()).unwrap();
        assert!(
            gate.receive(Request::Acknowledge { nonce: 7 }, None, 80, 900)
                .is_err()
        );
        assert!(gate.blocked());
        assert_eq!(gate.original_cut(), Some(80));
        let mut gate = executing(201);
        gate.record_reply(None, 14).unwrap();
        gate.sent(gate.next().unwrap()).unwrap();
        gate.receive(Request::Acknowledge { nonce: 7 }, None, 15, 900)
            .unwrap();
        assert!(
            gate.receive(
                Request::Begin {
                    nonce: 7,
                    control: 201
                },
                Some(scope(7, 201)),
                16,
                900
            )
            .is_err()
        );
        assert!(gate.blocked());
    }
}
