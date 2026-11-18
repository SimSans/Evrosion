//! Actual session-note namespace owner. Caller supplies an authenticated current
//! identity and a private copy of the shared proposal, never a shared Rust alias.
//! Ordinary operations freshly open/read Store. Probation reads require an exact
//! pre-Start exclusive-owner receipt; nonce/counter tags grant no authority.
use super::*;
use ev_app_registry::note_data::{BYTES, NoteDataEnvelope};
use ev_userspace_contract::session_note::{
    Operation, Outcome, Refusal, Request as NoteRequest, Response as NoteResponse,
};

pub struct NoteReply {
    pub response: NoteResponse,
    /// Only successful reads/exact durable write readbacks expose a body.
    pub bytes: Option<[u8; BYTES]>,
}
impl NoteReply {
    fn refused(request: NoteRequest, reason: Refusal) -> Self {
        Self {
            response: request.reply(Outcome::Refused(reason)),
            bytes: None,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum Failure {
    Storage,
    Stale,
    Malformed,
}

impl<T: Wire, W: Window> State<T, W> {
    fn note_begin(
        &mut self,
        packages: &impl Sources,
        identity: Identity,
        request: NoteRequest,
    ) -> Result<bool, Refusal> {
        if self.recovery_required() {
            return Err(Refusal::Recovery);
        }
        if !packages.is_session() || self.pending.is_some() {
            return Err(Refusal::Denied);
        }
        let Some(session) = self.session.as_ref() else {
            return Err(Refusal::Denied);
        };
        let Some(record) = self.record.as_ref() else {
            return Err(Refusal::Denied);
        };
        if session.identity != identity
            || record.app() != packages.app()
            || record
                .active()
                .is_none_or(|active| active.digest() != session.package)
        {
            return Err(Refusal::Denied);
        }
        let Some(slot) = packages.source(session.package) else {
            return Err(Refusal::Denied);
        };
        let Ok(package) = packages.checked_source(slot) else {
            return Err(Refusal::Denied);
        };
        let descriptor = package.app();
        if !descriptor
            .capability_requests()
            .any(|cap| cap.required && cap.capability == ev_zion::Capability::AppPrivateData)
            || !descriptor.contracts().any(|contract| {
                contract.name == ev_userspace_contract::session_note::INTERFACE
                    && contract.major == 1
                    && contract.minimum_minor == 0
                    && contract.features == 0
            })
        {
            return Err(Refusal::Denied);
        }
        if request.nonce() <= session.note_nonce {
            return Err(Refusal::Stale);
        }
        let health_probe = session.health_probation;
        // Consume the authenticated accepted nonce before decoding storage data.
        // Even a refused body cannot be resubmitted under the same nonce. Only
        // actual new admission resets this per-incarnation ledger.
        self.session.as_mut().unwrap().note_nonce = request.nonce();
        if health_probe && request.operation() == Operation::Write {
            // Health may complete after this authenticated request. No IO is
            // started; preserve the editor and require a new explicit nonce.
            return Err(Refusal::Busy);
        }
        Ok(health_probe)
    }
    /// Current authenticated new work is refused without reading the leased
    /// page or starting IO. The completed nonce cannot later authorize a write.
    pub fn note_busy(
        &mut self,
        packages: &impl Sources,
        identity: Identity,
        request: NoteRequest,
    ) -> NoteReply {
        let reason = self
            .note_begin(packages, identity, request)
            .err()
            .unwrap_or(Refusal::Busy);
        if reason != Refusal::Busy {
            self.invalidate_health_reads();
        }
        NoteReply::refused(request, reason)
    }
    /// No wire field selects an App, package, schema, region or operation ID.
    /// Only the actual admitted session may access this separate fixed namespace.
    #[inline(never)]
    pub fn note_request(
        &mut self,
        packages: &impl Sources,
        identity: Identity,
        request: NoteRequest,
        proposal: Option<&[u8; BYTES]>,
        deadline: u64,
    ) -> NoteReply {
        let reply = self.note_request_inner(packages, identity, request, proposal, deadline);
        // Busy accepted no IO or mutation. Preserve only authority that is
        // still present; backend loans and every unsafe refusal fence it.
        if matches!(reply.response.outcome(), Outcome::Refused(reason) if reason != Refusal::Busy) {
            self.invalidate_health_reads();
        }
        reply
    }
    fn note_request_inner(
        &mut self,
        packages: &impl Sources,
        identity: Identity,
        request: NoteRequest,
        proposal: Option<&[u8; BYTES]>,
        deadline: u64,
    ) -> NoteReply {
        let health_probe = match self.note_begin(packages, identity, request) {
            Ok(health_probe) => health_probe,
            Err(reason) => return NoteReply::refused(request, reason),
        };
        let proposed = match (request.operation(), proposal) {
            (Operation::Read, None) => None,
            (Operation::Write, Some(bytes)) => match NoteDataEnvelope::decode(bytes) {
                Ok(note)
                    if note.app() == packages.app() && note.expected_previous_counter().is_ok() =>
                {
                    Some(note)
                }
                _ => return NoteReply::refused(request, Refusal::Malformed),
            },
            _ => return NoteReply::refused(request, Refusal::Malformed),
        };
        if self.content_busy() {
            // Authenticated, canonical new work was NOT started. Its nonce is
            // consumed; only a later explicit request may use a fresh nonce.
            return NoteReply::refused(request, Refusal::Busy);
        }
        #[cfg(feature = "native-network")]
        if health_probe {
            return match self.retained_health_note(packages) {
                Ok(Some(note)) => NoteReply {
                    response: request.reply(Outcome::Read),
                    bytes: Some(note.encode()),
                },
                Ok(None) => NoteReply::refused(request, Refusal::Stale),
                Err(_) => NoteReply::refused(request, Refusal::Denied),
            };
        }
        if request.operation() == Operation::Write {
            self.invalidate_health_reads();
        }
        let result = (|| {
            let device = self.backend.device(Region::SessionNote, !health_probe);
            let mut store = match Store::open(device, deadline) {
                Ok(store) => store,
                Err(rejected) => {
                    // A generic read/corruption error never authorizes format.
                    if !matches!(rejected.error, ev_store::Error::Unformatted) {
                        return Err(Failure::Storage);
                    }
                    if health_probe {
                        return Err(Failure::Stale);
                    }
                    create_blank_note(
                        rejected.device,
                        packages,
                        proposed.map(|note| note.counter()),
                        deadline,
                    )?
                }
            };
            let old = validated_note(&mut store, packages, deadline)?;
            let mut actual = old.encode();
            if let Some(proposed) = proposed {
                let previous = proposed
                    .expected_previous_counter()
                    .map_err(|_| Failure::Malformed)?;
                let next = old
                    .checked_replace(packages.app(), previous, proposed.note())
                    .map_err(|_| Failure::Stale)?;
                if next != proposed || proposal.is_none_or(|bytes| *bytes != next.encode()) {
                    return Err(Failure::Malformed);
                }
                let operation = store.next_operation().map_err(|_| Failure::Storage)?;
                store
                    .execute(
                        operation,
                        Request::WriteMutable {
                            object: ObjectId::user_data(),
                            bytes: &next.encode(),
                        },
                        deadline,
                    )
                    .map_err(|_| Failure::Storage)?;
                let len = store
                    .read_mutable(ObjectId::user_data(), &mut actual, deadline)
                    .map_err(|_| Failure::Storage)?;
                if len != BYTES
                    || actual != next.encode()
                    || NoteDataEnvelope::decode(&actual) != Ok(next)
                {
                    return Err(Failure::Storage);
                }
                Ok(NoteReply {
                    response: request.reply(Outcome::Written),
                    bytes: Some(actual),
                })
            } else {
                Ok(NoteReply {
                    response: request.reply(Outcome::Read),
                    bytes: Some(actual),
                })
            }
        })();
        match result {
            Ok(reply) => {
                #[cfg(feature = "native-network")]
                if self.installed_for_fetch() {
                    // This path just validated the real ordinary Note Store
                    // read or exact durable write/readback, never a cached
                    // probation reply. The hint remains UI-only.
                    self.setup_hint = SetupHint::Ready;
                }
                reply
            }
            Err(Failure::Stale) => NoteReply::refused(request, Refusal::Stale),
            Err(Failure::Malformed) => NoteReply::refused(request, Refusal::Malformed),
            Err(Failure::Storage) => {
                self.recovery = true;
                self.session = None;
                NoteReply::refused(request, Refusal::Recovery)
            }
        }
    }
}

/// Shared sole-writer creation path. Every call reads the ENTIRE actual region
/// before format_new performs its own blank check. A retained UI hint, missing
/// root sector or stale proposal never permits writing existing Note bytes.
#[inline(never)]
pub(super) fn create_blank_note<I: ev_store::SectorIo>(
    mut device: I,
    packages: &impl Sources,
    proposed_counter: Option<u64>,
    deadline: u64,
) -> Result<Store<I>, Failure> {
    ev_store::desktop::require_blank(&mut device, deadline).map_err(|_| Failure::Storage)?;
    // Keep the ordinary App proposal's original order and stale semantics.
    if proposed_counter.is_some_and(|counter| counter != 1) {
        return Err(Failure::Stale);
    }
    let initial = NoteDataEnvelope::initial(packages.app(), "").map_err(|_| Failure::Malformed)?;
    Store::format_new(
        device,
        packages.note_format_manifest(),
        &initial.encode(),
        BootPolicy::new(1).unwrap(),
        deadline,
    )
    .map_err(|_| Failure::Storage)
}

/// Validate the real retained creation manifest and exact typed body. This is
/// shared with pre-Start preload; neither caller may infer a blank body.
#[inline(never)]
pub(super) fn validated_note<I: ev_store::SectorIo>(
    store: &mut Store<I>,
    packages: &impl Sources,
    deadline: u64,
) -> Result<NoteDataEnvelope, Failure> {
    let expected = packages.note_format_manifest();
    let created = store
        .selected_manifest(deadline)
        .map_err(|_| Failure::Storage)?;
    // Creation Root image is historical metadata, not current code.
    // Stable App/schema/region domain and ABI stay checked across A/B
    // and later compatible code replacement. Never invent data health.
    if created.generation != expected.generation
        || created.cohort != expected.cohort
        || created.abi != expected.abi
        || created.health_contract != expected.health_contract
        || created.health_version != expected.health_version
        || created.required_checks != expected.required_checks
        || created.supervisor_image == [0; 32]
        || store.known_good().is_some()
        || store
            .staged_manifest(deadline)
            .map_err(|_| Failure::Storage)?
            != Some(created)
    {
        return Err(Failure::Storage);
    }
    let mut actual = [0; BYTES];
    if store
        .read_mutable(ObjectId::user_data(), &mut actual, deadline)
        .map_err(|_| Failure::Storage)?
        != BYTES
    {
        return Err(Failure::Storage);
    }
    let old = NoteDataEnvelope::decode(&actual).map_err(|_| Failure::Storage)?;
    if old.app() != packages.app() {
        return Err(Failure::Storage);
    }
    Ok(old)
}

#[cfg(test)]
#[path = "note_state_tests.rs"]
mod tests;
