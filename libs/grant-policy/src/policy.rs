//! ONE bounded latest-policy slot using the actual Store transaction engine.
//! The source Root supplies the sole scoped device owner and actual consent and
//! live subject/resource projections. Identity/digests are never capabilities.
use ev_picker::{
    AppId, Delivery, ObjectView, ReadDelivery, Requester, UserId,
    intent::{self, PolicyHead, Record},
};
use ev_store::{BootPolicy, GenerationManifest, ObjectId, OperationId, Request, SectorIo, Store};
use sha2::{Digest as _, Sha256};

const BYTES: usize = intent::BYTES;
const _: () = assert!(BYTES == ev_store::PAYLOAD_BYTES);
/// The bounded actual File profile has no mutable external permission DB.
/// This is distinct from the durable policy's monotonically changing revision.
pub const FILE_PERMISSION_REVISION: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    pub user: UserId,
    pub app: AppId,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected {
    pub operation: OperationId,
    pub revision: u64,
    pub digest: [u8; 32],
}
#[derive(Clone, Copy, Debug)]
enum Slot {
    Empty(Scope),
    Grant(Record),
}
impl Slot {
    fn revision(self) -> u64 {
        match self {
            Self::Empty(_) => 0,
            Self::Grant(r) => r.policy_revision(),
        }
    }
    fn encode(self) -> [u8; BYTES] {
        match self {
            Self::Grant(record) => record.encode(),
            Self::Empty(scope) => {
                let mut b = [0; BYTES];
                b[..8].copy_from_slice(b"EVGEMP01");
                b[8..10].copy_from_slice(&1u16.to_le_bytes());
                b[16..32].copy_from_slice(&scope.user.bytes());
                b[32..48].copy_from_slice(&scope.app.bytes());
                let sum: [u8; 32] = Sha256::digest(&b[..224]).into();
                b[224..].copy_from_slice(&sum);
                b
            }
        }
    }
    fn decode(b: &[u8], scope: Scope) -> Result<Self, ()> {
        if b.len() != BYTES {
            return Err(());
        }
        if &b[..8] == b"EVGEMP01" {
            if b[8..10] != 1u16.to_le_bytes()
                || b[10..16].iter().chain(&b[48..224]).any(|n| *n != 0)
                || b[16..32] != scope.user.bytes()
                || b[32..48] != scope.app.bytes()
                || b[224..] != <[u8; 32]>::from(Sha256::digest(&b[..224]))
            {
                return Err(());
            }
            Ok(Self::Empty(scope))
        } else {
            let r = Record::decode(b).map_err(|_| ())?;
            if r.user() != scope.user || r.app().app != scope.app {
                return Err(());
            }
            Ok(Self::Grant(r))
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Store(ev_store::Error<E>),
    Policy(intent::Error),
    Corrupt,
    Scope,
    Stale,
    Empty,
    Active,
    Exhausted,
    NeedsRecovery,
    RecoveryConflict,
    Readback,
}
/// Move-only uncertain intent. Never allocate a new operation ID to retry it.
#[derive(Debug)]
pub struct Prepared {
    scope: Scope,
    base: Expected,
    bytes: [u8; BYTES],
}
impl Prepared {
    pub const fn operation(&self) -> OperationId {
        self.base.operation
    }
    pub fn after(&self) -> Record {
        Record::decode(&self.bytes).expect("prepared canonical grant")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Published {
    pub operation: OperationId,
    pub sequence: u64,
    pub revision: u64,
    pub recovered: bool,
}
#[allow(clippy::large_enum_variant)] // Bounded owned intent, no alloc/Box.
pub enum Resolution {
    NoPending,
    Unpublished(Prepared),
    Committed(Published),
}
pub struct Rejected<D: SectorIo> {
    pub device: D,
    pub scope: Scope,
    pub pending: Option<Prepared>,
    pub error: Error<D::Error>,
}
/// The receipt is policy eligibility, NOT authority, a simulated handle, or a
/// serialized Picker consent. The actual callback rechecks live process/source
/// capabilities and uses generic managed delivery immediately before enqueue.
/// Its views are immutable and only a current PolicyOwner can construct it.
/// ```compile_fail,E0616
/// use ev_grant_policy::Eligible;
/// fn replace_head(value: &mut Eligible<'_>) { value.head.revision = 0; }
/// ```
pub struct Eligible<'a> {
    record: &'a Record,
    head: PolicyHead,
    requester: Requester,
    object: ObjectView,
}
impl Eligible<'_> {
    pub const fn record(&self) -> &Record {
        self.record
    }
    pub const fn head(&self) -> PolicyHead {
        self.head
    }
    pub const fn requester(&self) -> Requester {
        self.requester
    }
    pub const fn object(&self) -> ObjectView {
        self.object
    }
}
pub trait FreshReadHandoff {
    type Ticket;
    type Error;
    fn enqueue_fresh_read(&mut self, eligible: Eligible<'_>)
    -> Delivery<Self::Ticket, Self::Error>;
}
pub type RemintResult<Ticket, HandoffError, DeviceError> =
    Result<Delivery<Ticket, HandoffError>, Error<DeviceError>>;
/// Sole trusted owner of the entire14-sector region. No second backend/alias
/// may mutate it while this owner lives. Lifecycle registry is a separate state
/// type; this is the one latest grant-policy index for the bounded owner/App.
pub struct PolicyOwner<D: SectorIo> {
    store: Store<D>,
    scope: Scope,
    slot: Slot,
    pending: Option<Prepared>,
    recovery: bool,
}
impl<D: SectorIo> PolicyOwner<D> {
    /// Bounded scoped owner: the actual State backend is exclusively reborrowed
    /// during this call; no detached Store or Window escapes into Root's loop.
    /// Every refusal returns that device and exact unresolved publication.
    #[allow(clippy::result_large_err)]
    #[inline(never)]
    pub fn with_open<T>(
        device: D,
        scope: Scope,
        deadline: u64,
        operation: impl FnOnce(&mut Self) -> Result<T, Error<D::Error>>,
    ) -> Result<(D, T), Rejected<D>> {
        let mut owner = Self::open(device, scope, deadline)?;
        let result = operation(&mut owner);
        let recovery = owner.recovery;
        let (device, scope, pending) = owner.into_parts();
        match result {
            Ok(value) if pending.is_none() && !recovery => Ok((device, value)),
            Ok(_) => Err(Rejected {
                device,
                scope,
                pending,
                error: Error::NeedsRecovery,
            }),
            Err(error) => Err(Rejected {
                device,
                scope,
                pending,
                error,
            }),
        }
    }
    /// Explicit blank-only namespace allocation; not an approved File grant.
    /// Integration invokes it only from a real owner-authorized allocation.
    /// Partial first allocation fails closed; it is not a WriteMutable proof.
    #[allow(clippy::result_large_err)]
    pub fn format_empty(
        device: D,
        scope: Scope,
        context: GenerationManifest,
        deadline: u64,
    ) -> Result<Self, Rejected<D>> {
        let slot = Slot::Empty(scope);
        let store = Store::format_new(
            device,
            context,
            &slot.encode(),
            BootPolicy::new(1).unwrap(),
            deadline,
        )
        .map_err(|r| Rejected {
            device: r.device,
            scope,
            pending: None,
            error: Error::Store(r.error),
        })?;
        Ok(Self {
            store,
            scope,
            slot,
            pending: None,
            recovery: false,
        })
    }
    #[allow(clippy::result_large_err)]
    pub fn open(device: D, scope: Scope, deadline: u64) -> Result<Self, Rejected<D>> {
        let mut store = Store::open(device, deadline).map_err(|r| Rejected {
            device: r.device,
            scope,
            pending: None,
            error: Error::Store(r.error),
        })?;
        let slot = match load(&mut store, scope, deadline) {
            Ok(slot) => slot,
            Err(error) => {
                return Err(Rejected {
                    device: store.into_device(),
                    scope,
                    pending: None,
                    error,
                });
            }
        };
        Ok(Self {
            store,
            scope,
            slot,
            pending: None,
            recovery: false,
        })
    }
    pub fn expected(&self) -> Result<Expected, Error<D::Error>> {
        if self.pending.is_some() || self.recovery {
            return Err(Error::NeedsRecovery);
        }
        Ok(Expected {
            operation: self.store.next_operation().map_err(Error::Store)?,
            revision: self.slot.revision(),
            digest: Sha256::digest(self.slot.encode()).into(),
        })
    }
    pub fn record(&self) -> Result<Option<Record>, Error<D::Error>> {
        self.expected()?;
        Ok(match self.slot {
            Slot::Empty(_) => None,
            Slot::Grant(r) => Some(r),
        })
    }
    /// Initial no-policy requester revision1, otherwise latest persisted
    /// revision. This is separate from the immutable File permission revision.
    pub fn requester_policy_revision(&self) -> Result<u64, Error<D::Error>> {
        self.expected()?;
        Ok(self.slot.revision().max(1))
    }
    pub fn prepare_remember(
        &self,
        expected: Expected,
        delivery: &ReadDelivery<'_>,
    ) -> Result<Prepared, Error<D::Error>> {
        if self.expected()? != expected {
            return Err(Error::Stale);
        }
        let requester = delivery.selection().requester();
        if requester.user != self.scope.user || requester.app.app != self.scope.app {
            return Err(Error::Scope);
        }
        if requester.policy_revision != self.requester_policy_revision()? {
            return Err(Error::Stale);
        }
        if delivery.selection().object().permission_revision != FILE_PERMISSION_REVISION {
            return Err(Error::Policy(intent::Error::Denied));
        }
        let serial = match self.slot {
            Slot::Empty(_) => 1,
            Slot::Grant(r) if r.revoked() => increment(r.grant_serial())?,
            Slot::Grant(_) => return Err(Error::Active),
        };
        let revision = increment(expected.revision)?;
        let record = Record::proposed(delivery, serial, revision).map_err(Error::Policy)?;
        Ok(Prepared {
            scope: self.scope,
            base: expected,
            bytes: record.encode(),
        })
    }
    /// Durable tombstone metadata only. The actual integration first fences new
    /// remints and retires the live pending/current branches (bounded proof may
    /// stop/reap App), then publishes and acknowledges only after readback.
    pub fn prepare_revoke(&self, expected: Expected) -> Result<Prepared, Error<D::Error>> {
        if self.expected()? != expected {
            return Err(Error::Stale);
        }
        let Slot::Grant(mut record) = self.slot else {
            return Err(Error::Empty);
        };
        if record.revoked() {
            return Err(Error::Policy(intent::Error::Revoked));
        }
        record.revoke().map_err(Error::Policy)?;
        Ok(Prepared {
            scope: self.scope,
            base: expected,
            bytes: record.encode(),
        })
    }
    /// Own intent BEFORE first mutation. Every execute/readback error keeps it
    /// and refuses all remints/publications until the same operation is resolved.
    pub fn publish(
        &mut self,
        intent: Prepared,
        deadline: u64,
    ) -> Result<Published, Error<D::Error>> {
        if self.expected()? != intent.base || intent.scope != self.scope {
            return Err(Error::Stale);
        }
        let after = Slot::decode(&intent.bytes, self.scope).map_err(|_| Error::Corrupt)?;
        self.pending = Some(intent);
        let intent = self.pending.as_ref().unwrap();
        let receipt = self
            .store
            .execute(
                intent.base.operation,
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &intent.bytes,
                },
                deadline,
            )
            .map_err(Error::Store)?;
        let actual = load(&mut self.store, self.scope, deadline)?;
        if actual.encode() != intent.bytes
            || receipt.operation != intent.base.operation
            || receipt.sequence
                != intent
                    .base
                    .operation
                    .get()
                    .checked_add(1)
                    .ok_or(Error::Exhausted)?
            || self.store.next_operation().map_err(Error::Store)?.get() != receipt.sequence
        {
            return Err(Error::Readback);
        }
        let result = Published {
            operation: receipt.operation,
            sequence: receipt.sequence,
            revision: after.revision(),
            recovered: false,
        };
        self.slot = actual;
        self.pending = None;
        Ok(result)
    }
    /// Reload the authoritative current slot after Store recovery. Caller has
    /// already fenced old writers and independently restored a usable backend.
    /// No transport retry or fresh operation ID is invented here.
    #[allow(clippy::result_large_err)]
    pub fn resume(
        device: D,
        scope: Scope,
        pending: Option<Prepared>,
        deadline: u64,
    ) -> Result<(Self, Resolution), Rejected<D>> {
        if pending.as_ref().is_some_and(|p| p.scope != scope) {
            return Err(Rejected {
                device,
                scope,
                pending,
                error: Error::RecoveryConflict,
            });
        }
        let owner = match Self::open(device, scope, deadline) {
            Ok(owner) => owner,
            Err(mut refused) => {
                refused.pending = pending;
                return Err(refused);
            }
        };
        let resolution = match pending {
            None => Resolution::NoPending,
            Some(p) => {
                let actual = match owner.expected() {
                    Ok(head) => head,
                    Err(error) => {
                        return Err(Rejected {
                            device: owner.store.into_device(),
                            scope,
                            pending: Some(p),
                            error,
                        });
                    }
                };
                if actual == p.base {
                    Resolution::Unpublished(p)
                } else if p.base.operation.get().checked_add(1) == Some(actual.operation.get())
                    && owner.slot.encode() == p.bytes
                {
                    Resolution::Committed(Published {
                        operation: p.base.operation,
                        sequence: actual.operation.get(),
                        revision: actual.revision,
                        recovered: true,
                    })
                } else {
                    return Err(Rejected {
                        device: owner.store.into_device(),
                        scope,
                        pending: Some(p),
                        error: Error::RecoveryConflict,
                    });
                }
            }
        };
        Ok((owner, resolution))
    }
    /// Policy check only. Exact current live capability/source/inbox/request
    /// provenance must be revalidated by the actual handoff, never this codec.
    pub fn remint<H: FreshReadHandoff>(
        &mut self,
        current: Requester,
        object: ObjectView,
        deadline: u64,
        handoff: &mut H,
    ) -> RemintResult<H::Ticket, H::Error, D::Error> {
        self.expected()?;
        self.slot = match load(&mut self.store, self.scope, deadline) {
            Ok(slot) => slot,
            Err(error) => {
                self.recovery = true;
                return Err(error);
            }
        };
        let Slot::Grant(record) = &self.slot else {
            return Err(Error::Empty);
        };
        if current.policy_revision != record.policy_revision() {
            return Err(Error::Stale);
        }
        if object.permission_revision != FILE_PERMISSION_REVISION {
            return Err(Error::Policy(intent::Error::Denied));
        }
        record
            .validate_activation(record.head(), current, object)
            .map_err(Error::Policy)?;
        Ok(handoff.enqueue_fresh_read(Eligible {
            record,
            head: record.head(),
            requester: current,
            object,
        }))
    }
    pub fn into_parts(self) -> (D, Scope, Option<Prepared>) {
        (self.store.into_device(), self.scope, self.pending)
    }
}
fn load<D: SectorIo>(
    store: &mut Store<D>,
    scope: Scope,
    deadline: u64,
) -> Result<Slot, Error<D::Error>> {
    let mut bytes = [0; BYTES];
    if store
        .read_mutable(ObjectId::user_data(), &mut bytes, deadline)
        .map_err(Error::Store)?
        != BYTES
    {
        return Err(Error::Corrupt);
    }
    let slot = Slot::decode(&bytes, scope).map_err(|_| Error::Corrupt)?;
    // This namespace performs exactly one policy revision per Store operation;
    // boot/generation mutations and re-publishing an old record under a fresh
    // operation cannot become an authoritative latest permission head.
    if slot.revision().checked_add(1) != Some(store.next_operation().map_err(Error::Store)?.get())
        || store.known_good().is_some()
        || store.committed_boot_serial().map_err(Error::Store)? != 0
        || store.last_failure().map_err(Error::Store)?.is_some()
    {
        return Err(Error::Corrupt);
    }
    if let Slot::Grant(record) = slot
        && record.grant_serial() > record.policy_revision()
    {
        return Err(Error::Corrupt);
    }
    Ok(slot)
}
fn increment<E>(old: u64) -> Result<u64, Error<E>> {
    old.checked_add(1)
        .filter(|v| *v != u64::MAX)
        .ok_or(Error::Exhausted)
}
