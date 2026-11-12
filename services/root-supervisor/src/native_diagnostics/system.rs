//! Read-only inspection of committed System metadata. It neither selects a
//! boot generation nor certifies that the current Native process belongs to it.
use core::fmt::{self, Write};
use ev_store::{GenerationManifest, LastFailure, Sector, SectorIo, Store};
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Read(E),
    RecoveryWouldWrite,
}
pub struct ReadOnly<D>(pub D);
impl<D: SectorIo> SectorIo for ReadOnly<D> {
    type Error = Error<D::Error>;
    fn sectors(&self) -> u64 {
        self.0.sectors()
    }
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Self::Error> {
        self.0.read(lba, out, deadline).map_err(Error::Read)
    }
    fn write(&mut self, _: u64, _: &Sector, _: u64) -> Result<(), Self::Error> {
        Err(Error::RecoveryWouldWrite)
    }
    fn flush(&mut self, _: u64) -> Result<(), Self::Error> {
        Err(Error::RecoveryWouldWrite)
    }
}
// No heap: retain one bounded actual durable-metadata observation by value.
#[allow(clippy::large_enum_variant)]
pub enum State {
    NotCollected,
    Unformatted,
    NeedsRecovery,
    Unavailable,
    Committed {
        selected: GenerationManifest,
        known_good: Option<u64>,
        last_failure: Option<LastFailure>,
    },
}
impl State {
    pub fn snapshot(&self, first_tick: u64, last_tick: u64) -> ev_diagnostics::system::Snapshot {
        use ev_diagnostics::system::{Failure, Manifest, Snapshot, State as Kind};
        match self {
            Self::NotCollected => Snapshot::new(Kind::NotCollected, first_tick, last_tick),
            Self::Unformatted => Snapshot::new(Kind::Unformatted, first_tick, last_tick),
            Self::NeedsRecovery => Snapshot::new(Kind::NeedsRecovery, first_tick, last_tick),
            Self::Unavailable => Snapshot::new(Kind::Unavailable, first_tick, last_tick),
            Self::Committed {
                selected,
                known_good,
                last_failure,
            } => Snapshot {
                state: Kind::Committed,
                first_tick,
                last_tick,
                selected: Some(Manifest {
                    generation: selected.generation.get(),
                    cohort: selected.cohort,
                    supervisor_image: selected.supervisor_image,
                    abi: selected.abi,
                    health_contract: selected.health_contract,
                    health_version: selected.health_version,
                    required_checks: selected.required_checks,
                }),
                known_good: *known_good,
                last_failure: last_failure.map(|f| Failure {
                    generation: f.generation.get(),
                    boot_serial: f.boot_serial,
                    attempts: f.attempts,
                    reason: match f.reason {
                        ev_store::LastFailureReason::ProcessFault => 1,
                        ev_store::LastFailureReason::MissingProgress => 2,
                        ev_store::LastFailureReason::StorageFailure => 3,
                        ev_store::LastFailureReason::AttemptBudgetExhausted => 4,
                    },
                    supervisor_image: f.supervisor_image,
                    process_stamp: f.process_stamp,
                    operation: f.operation.get(),
                    sequence: f.sequence,
                }),
                current: None,
            },
        }
    }
    pub fn write(&self, out: &mut impl Write) -> fmt::Result {
        writeln!(
            out,
            "Current Native boot System generation: unknown; no matched durable selection/admission receipt."
        )?;
        match self {
            Self::NotCollected => writeln!(out, "System Store metadata: not collected."),
            Self::Unformatted => writeln!(
                out,
                "System Store metadata: unformatted; no selected generation or Known Good inferred."
            ),
            Self::NeedsRecovery => writeln!(
                out,
                "System Store metadata: recovery required; inspector refused every write/flush."
            ),
            Self::Unavailable => writeln!(
                out,
                "System Store metadata: unavailable/corrupt; no health or Known Good inferred."
            ),
            Self::Committed {
                selected,
                known_good,
                last_failure,
            } => {
                writeln!(
                    out,
                    "Durable System metadata (not current-execution attestation): selected generation {} | Known Good {:?}",
                    selected.generation.get(),
                    known_good
                )?;
                write!(out, "  selected cohort ")?;
                ev_diagnostics::live::hex(out, &selected.cohort)?;
                write!(out, "\n  selected supervisor ")?;
                ev_diagnostics::live::hex(out, &selected.supervisor_image)?;
                writeln!(out)?;
                if let Some(failure) = last_failure {
                    writeln!(
                        out,
                        "  retained failure: generation {} boot serial {} reason {:?}",
                        failure.generation.get(),
                        failure.boot_serial,
                        failure.reason
                    )?;
                }
                Ok(())
            }
        }
    }
}
/// The original device is always returned. No uncertain read/recovery result
/// causes formatting, data mutation, retry or a synthetic KnownGood/health claim.
#[inline(never)]
pub fn inspect<D: SectorIo>(device: D, deadline: u64) -> (D, State) {
    let mut store = match Store::open(ReadOnly(device), deadline) {
        Ok(store) => store,
        Err(rejected) => {
            let state = match rejected.error {
                ev_store::Error::Unformatted => State::Unformatted,
                ev_store::Error::Io(Error::RecoveryWouldWrite)
                | ev_store::Error::RecoveryRequired
                | ev_store::Error::NeedsRecovery => State::NeedsRecovery,
                _ => State::Unavailable,
            };
            return (rejected.device.0, state);
        }
    };
    let selected = store.selected_manifest(deadline);
    let state = match (selected, store.last_failure()) {
        (Ok(selected), Ok(last_failure)) => State::Committed {
            selected,
            known_good: store.known_good().map(|id| id.get()),
            last_failure,
        },
        (Err(ev_store::Error::RecoveryRequired), _) => State::NeedsRecovery,
        _ => State::Unavailable,
    };
    (store.into_device().0, state)
}
