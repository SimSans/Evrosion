//! Trusted Root-owned single AppData allocation. Metadata is not authority;
//! enrollment and endpoint/caller policy must be established independently.
use super::Device;
use ev_app_registry::app_data::AppDataEnvelope;
use ev_block_service::store_io::{Window, Wire};
use ev_store::{GenerationManifest, MutablePayload, ObjectId, OperationId, Request, Store};
use ev_zion::AppId;

/// Independently retained original format/allocation identity, never inferred
/// from current media, a claimed app ID or a later replacement package. This
/// reference supports ONE fixed NEW external AppData region, not arbitrary
/// app-selected allocations, physical sectors or a multi-app allocator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allocation {
    creation: GenerationManifest,
    app: AppId,
    schema_epoch: u32,
}
impl Allocation {
    pub fn new(creation: GenerationManifest, app: AppId, schema_epoch: u32) -> Option<Self> {
        (creation.valid() && creation.health_version == 1 && schema_epoch != 0).then_some(Self {
            creation,
            app,
            schema_epoch,
        })
    }
    pub const fn app(&self) -> AppId {
        self.app
    }
    pub const fn schema_epoch(&self) -> u32 {
        self.schema_epoch
    }
    pub const fn creation(&self) -> &GenerationManifest {
        &self.creation
    }
    fn decode(self, bytes: &[u8]) -> Result<AppDataEnvelope, ev_app_registry::app_data::Error> {
        let value = AppDataEnvelope::decode(bytes)?;
        if value.app() != self.app {
            return Err(ev_app_registry::app_data::Error::Identity);
        }
        if value.schema_epoch() != self.schema_epoch {
            return Err(ev_app_registry::app_data::Error::Epoch);
        }
        Ok(value)
    }
    fn accepts(self, payload: MutablePayload<'_>) -> bool {
        let (committed, proposed) = match payload {
            MutablePayload::Committed(bytes) => return self.decode(bytes).is_ok(),
            MutablePayload::Pending {
                committed,
                proposed,
            } => (committed, proposed),
        };
        let Ok(old) = self.decode(committed) else {
            return false;
        };
        let Ok(next) = self.decode(proposed) else {
            return false;
        };
        // Recovery accepts only the exact next counter. A valid same-app/schema
        // envelope with a reset/skipped counter is not a valid replacement.
        old.counter()
            .checked_add(1)
            .is_some_and(|counter| counter != u64::MAX && next.counter() == counter)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Store(ev_store::Error<E>),
    Envelope(ev_app_registry::app_data::Error),
    Readback,
    Retained,
}
/// The rejected exact device borrow is retained on every checked-open refusal.
pub type OpenResult<'a, T, W> =
    Result<PrivateData<Device<'a, T, W>>, ev_store::RejectedDevice<Device<'a, T, W>>>;

/// Exact accepted operation and frozen proposal retained through uncertainty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    pub operation: OperationId,
    pub proposal: AppDataEnvelope,
}

/// This wrapper exposes no Store, raw SectorIo, backend splitting or fallback
/// formatting path. Drop is not quiescence or permission for reconstruction.
pub struct PrivateData<D: ev_store::SectorIo> {
    store: Store<D>,
    allocation: Allocation,
    pending: Option<Pending>,
    retained: bool,
}
pub(crate) fn open<'a, T: Wire, W: Window>(
    device: Device<'a, T, W>,
    allocation: Allocation,
    deadline: u64,
) -> OpenResult<'a, T, W> {
    let store = Store::open_mutable_namespace_checked(
        device,
        allocation.creation(),
        |payload| allocation.accepts(payload),
        deadline,
    )?;
    Ok(PrivateData {
        store,
        allocation,
        pending: None,
        retained: false,
    })
}
impl<D: ev_store::SectorIo> PrivateData<D> {
    pub const fn pending(&self) -> Option<Pending> {
        self.pending
    }
    pub fn read(&mut self, deadline: u64) -> Result<AppDataEnvelope, Error<D::Error>> {
        if self.retained || self.pending.is_some() {
            return Err(Error::Retained);
        }
        self.read_inner(deadline)
    }
    fn read_inner(&mut self, deadline: u64) -> Result<AppDataEnvelope, Error<D::Error>> {
        let mut bytes = [0; ev_store::PAYLOAD_BYTES];
        let len = self
            .store
            .read_mutable(ObjectId::user_data(), &mut bytes, deadline)
            .map_err(Error::Store)?;
        self.allocation
            .decode(&bytes[..len])
            .map_err(Error::Envelope)
    }
    /// Prepares an exact next-counter write, then commits and independently
    /// reads the full envelope before returning. No retry clears uncertainty.
    pub fn replace(
        &mut self,
        expected_counter: u64,
        value: u32,
        deadline: u64,
    ) -> Result<AppDataEnvelope, Error<D::Error>> {
        if self.retained || self.pending.is_some() {
            return Err(Error::Retained);
        }
        let old = self.read_inner(deadline)?;
        let proposal = old
            .checked_replace(
                self.allocation.app(),
                self.allocation.schema_epoch(),
                expected_counter,
                value,
            )
            .map_err(Error::Envelope)?;
        let operation = self.store.next_operation().map_err(Error::Store)?;
        self.pending = Some(Pending {
            operation,
            proposal,
        });
        self.store
            .execute(
                operation,
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &proposal.encode(),
                },
                deadline,
            )
            .map_err(Error::Store)?;
        match self.read_inner(deadline) {
            Ok(readback) if readback == proposal => {
                self.pending = None;
                Ok(readback)
            }
            Ok(_) => {
                self.retained = true;
                Err(Error::Readback)
            }
            Err(error) => {
                self.retained = true;
                Err(error)
            }
        }
    }
}
