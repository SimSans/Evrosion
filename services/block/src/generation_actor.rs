//! Measured userspace generation policy. The kernel supplies capabilities,
//! authenticated sender diagnostics and actual lifecycle/fault mechanisms;
//! catalogue resolution, persistent operations and named health live here.
use super::{require, rpc_actor::Window};
use ev_block_service::{
    GenerationCapabilities,
    store_io::{Endpoint, StoreRegion, Window as _, Wire},
};
use ev_store::{
    AdmissionReport, BootPlan, BootPolicy, GenerationId, GenerationManifest, HealthOutcome,
    HealthReport, LastFailure, LastFailureReason, ObjectId, Store,
};
use ev_userspace_contract::{
    Bootstrap, Event,
    block::{Request as BlockRequest, Response},
    generation::{
        Catalogue, Completion, Control, Digest, HEALTH_DESCRIPTION, Mode, OwnerDecision, Slot,
    },
    syscall,
};
use ev_userspace_runtime::{self as rt, SyncEndpoint};
use sha2::{Digest as _, Sha256};

type RawDevice = StoreRegion<Endpoint, Window>;
#[cfg(not(feature = "test-owner-client"))]
type Device = RawDevice;
#[cfg(feature = "test-owner-client")]
type Device = ev_block_service::store_io::WriteGate<RawDevice>;
type Failure = ev_store::Error<<Device as ev_store::SectorIo>::Error>;
const OWNER_A: &[u8] = b"owner-data-A";
const OWNER_B: &[u8] = b"owner-data-B";
fn failed(stage: u64, error: Failure) -> ! {
    let detail = match error {
        ev_store::Error::Io(_) => 1,
        ev_store::Error::Corrupt => 2,
        ev_store::Error::StaleHealth => 3,
        ev_store::Error::Phase => 4,
        ev_store::Error::RecoveryRequired => 5,
        _ => 6,
    };
    rt::exit((stage << 32) | detail)
}
fn value(number: u64, a: u64, b: u64, c: u64) -> u64 {
    let reply = rt::call(number, a, b, c);
    require(reply.status == 0 && reply.capability == 0, 400 + number);
    reply.value
}
fn now() -> u64 {
    value(syscall::MONOTONIC, 0, 0, 0)
}
fn yield_now() {
    require(value(syscall::YIELD, 0, 0, 0) == 0, 440);
}
fn hash(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}
fn manifest(catalogue: Catalogue, slot: Slot, generation: u64) -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(generation).unwrap_or_else(|| rt::exit(441)),
        cohort: hash(&catalogue.cohort_input_for(slot, generation)),
        supervisor_image: catalogue.image(slot),
        abi: catalogue.abi,
        health_contract: catalogue.health,
        health_version: catalogue.health_version,
        required_checks: u32::from(catalogue.required_checks),
    }
}
fn resolve(catalogue: Catalogue, selected: &GenerationManifest) -> Option<Slot> {
    [Slot::A, Slot::B]
        .into_iter()
        .find(|slot| manifest(catalogue, *slot, selected.generation.get()) == *selected)
}
#[inline(never)]
fn catalogue(record: u64) -> (Catalogue, Digest) {
    let address = record
        .checked_sub(2 * 4096)
        .unwrap_or_else(|| rt::exit(442));
    let mut bytes = [0u8; 512];
    for (i, byte) in bytes.iter_mut().enumerate() {
        // SAFETY: exact read-only role8 catalogue at page507, retained by the
        // ordinary controller mapping owner; no writable Rust alias is created.
        *byte = unsafe { (address as *const u8).add(i).read_volatile() };
    }
    let catalogue = Catalogue::decode(&bytes).unwrap_or_else(|_| rt::exit(443));
    require(
        catalogue.abi == ev_userspace_contract::ABI && catalogue.health == hash(HEALTH_DESCRIPTION),
        444,
    );
    (catalogue, hash(&bytes))
}
#[inline(never)]
fn control(endpoint: &mut Endpoint, window: &Window, deadline: u64) -> Control {
    let request = BlockRequest::Read { sector: 2 };
    let reply = endpoint
        .call(request.encode(), deadline)
        .unwrap_or_else(|_| rt::exit(445));
    require(Response::decode(&reply) == Ok(request.success()), 446);
    let mut bytes = [0; 512];
    window.load(&mut bytes);
    Control::decode(&bytes).unwrap_or_else(|_| rt::exit(447))
}
#[inline(never)]
fn request(
    store: &mut Store<Device>,
    request: ev_store::Request<'_>,
    deadline: u64,
) -> ev_store::Receipt {
    let id = store.next_operation().unwrap_or_else(|e| failed(448, e));
    let receipt = store
        .execute(id, request, deadline)
        .unwrap_or_else(|e| failed(449, e));
    require(
        receipt.operation == id && receipt.sequence == id.get() + 1 && !receipt.replayed,
        450,
    );
    receipt
}
#[inline(never)]
fn payload(store: &mut Store<Device>, expected: &[u8], deadline: u64) -> Digest {
    let mut bytes = [0; ev_store::PAYLOAD_BYTES];
    let len = store
        .read_mutable(ObjectId::user_data(), &mut bytes, deadline)
        .unwrap_or_else(|e| failed(451, e));
    require(&bytes[..len] == expected, 452);
    hash(&bytes[..len])
}
#[inline(never)]
fn probe(store: &mut Store<Device>, expected: &[u8], deadline: u64) -> Digest {
    request(
        store,
        ev_store::Request::WriteMutable {
            object: ObjectId::user_data(),
            bytes: expected,
        },
        deadline,
    );
    payload(store, expected, deadline)
}
#[inline(never)]
fn format(device: Device, catalogue: Catalogue, deadline: u64) -> Store<Device> {
    Store::format_new(
        device,
        manifest(catalogue, Slot::A, 1),
        OWNER_A,
        BootPolicy::new(3).unwrap(),
        deadline,
    )
    .unwrap_or_else(|e| failed(453, e.error))
}
#[inline(never)]
fn open(device: Device, deadline: u64) -> Store<Device> {
    Store::open(device, deadline).unwrap_or_else(|e| failed(454, e.error))
}
#[derive(Clone, Copy)]
struct Identity {
    process: u64,
    thread: u64,
}
fn identity(process: u64) -> Identity {
    let reply = rt::call(syscall::PROCESS_IDENTITY, process, 0, 0);
    require(
        reply.status == 0 && reply.value != 0 && reply.capability != 0,
        455,
    );
    Identity {
        process: reply.value,
        thread: reply.capability,
    }
}
#[derive(Default)]
struct Seen {
    generic: bool,
    critical: bool,
}
enum Received {
    Current,
    OwnSpoof,
    Foreign,
}
/// Only authenticated exact current process/thread events can update Seen.
fn receive(
    caps: GenerationCapabilities,
    actual: Option<Identity>,
    own: u64,
    seen: &mut Seen,
) -> Option<Received> {
    let reply = rt::call4(syscall::RECEIVE_EVENT, caps.event_rx, 0, 0, 0);
    if reply.status == 2 {
        require(
            reply.value == 0 && reply.capability == 0 && reply.serial == 0,
            456,
        );
        return None;
    }
    require(
        reply.status == 0 && reply.capability != 0 && reply.serial != 0,
        457,
    );
    let event = Event::decode(&reply.value.to_le_bytes()).unwrap_or_else(|| rt::exit(458));
    if actual.is_some_and(|id| id.process == reply.capability && id.thread == reply.serial) {
        match event {
            Event::Ready => {
                require(!seen.generic, 459);
                seen.generic = true;
            }
            Event::CriticalReady => {
                require(seen.generic && !seen.critical, 460);
                seen.critical = true;
            }
            _ => rt::exit(461),
        }
        Some(Received::Current)
    } else {
        // Foreign/stale events never establish readiness. The explicit negative
        // suite sends from this actual controller, so record its mismatch.
        Some(if reply.capability == own {
            Received::OwnSpoof
        } else {
            Received::Foreign
        })
    }
}
fn spoof(
    caps: GenerationCapabilities,
    actual: Option<Identity>,
    own: u64,
    seen: &mut Seen,
    limit: u64,
) -> u64 {
    let mut rejected = 0;
    for event in [Event::Ready, Event::CriticalReady] {
        require(rt::send(caps.event_tx, event.encode()).status == 0, 463);
        loop {
            if let Some(Received::OwnSpoof) = receive(caps, actual, own, seen) {
                rejected += 1;
                break;
            }
            require(now() < limit, 464);
            yield_now();
        }
    }
    rejected
}
fn stamp(catalogue: Catalogue, plan: BootPlan, id: Identity) -> Digest {
    let mut hash = Sha256::new();
    hash.update(b"evrosion.actual.generation.admission.v1\0");
    hash.update(catalogue.kernel_build);
    hash.update(plan.manifest.generation.get().to_le_bytes());
    hash.update(plan.serial.to_le_bytes());
    hash.update(id.process.to_le_bytes());
    hash.update(id.thread.to_le_bytes());
    hash.update(plan.manifest.cohort);
    hash.update(plan.manifest.supervisor_image);
    hash.finalize().into()
}
fn admission(catalogue: Catalogue, plan: BootPlan, id: Identity) -> AdmissionReport {
    AdmissionReport {
        generation: plan.manifest.generation,
        boot_serial: plan.serial,
        process_stamp: stamp(catalogue, plan, id),
        cohort: plan.manifest.cohort,
        supervisor_image: plan.manifest.supervisor_image,
        abi: plan.manifest.abi,
        health_contract: plan.manifest.health_contract,
        health_version: plan.manifest.health_version,
    }
}
#[inline(never)]
fn reject_health(
    store: &mut Store<Device>,
    admitted: AdmissionReport,
    storage_probe: Digest,
    deadline: u64,
) {
    let id = store.next_operation().unwrap_or_else(|e| failed(465, e));
    require(
        matches!(
            store.execute(
                id,
                ev_store::Request::Health(HealthReport {
                    admitted,
                    outcome: HealthOutcome::CriticalPassed,
                    observed_checks: 3,
                    storage_probe
                }),
                deadline
            ),
            Err(ev_store::Error::StaleHealth)
        ),
        466,
    );
    require(
        store.next_operation().unwrap_or_else(|e| failed(467, e)) == id,
        468,
    );
}
#[derive(Clone, Copy)]
struct Booted {
    plan: BootPlan,
    id: Identity,
    stamp: Digest,
    negatives: u64,
    probe: Digest,
    outcome: HealthOutcome,
}
#[inline(never)]
fn boot(
    store: &mut Store<Device>,
    catalogue: Catalogue,
    caps: GenerationCapabilities,
    own: u64,
    expected: &[u8],
    deadline: u64,
    stop: u64,
) -> Booted {
    let selected = store
        .selected_manifest(deadline)
        .unwrap_or_else(|e| failed(469, e));
    resolve(catalogue, &selected).unwrap_or_else(|| rt::exit(470));
    request(
        store,
        ev_store::Request::BeginBoot(selected.generation),
        deadline,
    );
    let plan = store.boot_plan(deadline).unwrap_or_else(|e| failed(471, e));
    // Durable attempt charging may exhaust a candidate and select KnownGood.
    // Resolve the committed returned plan, rather than admitting cached B bytes
    // after the store has correctly selected A for this actual boot serial.
    require(
        plan.serial
            == store
                .committed_boot_serial()
                .unwrap_or_else(|e| failed(471, e))
            && plan.attempt != 0,
        472,
    );
    let slot = resolve(catalogue, &plan.manifest).unwrap_or_else(|| rt::exit(470));
    let storage_probe = payload(store, expected, deadline);
    let mut fake = admission(
        catalogue,
        plan,
        Identity {
            process: own,
            thread: 1,
        },
    );
    fake.process_stamp = [0x5a; 32];
    reject_health(store, fake, storage_probe, deadline);
    let mut seen = Seen::default();
    let mut negatives = spoof(caps, None, own, &mut seen, stop);
    require(!seen.generic && !seen.critical, 473);
    let image = match slot {
        Slot::A => caps.image_a,
        Slot::B => caps.image_b,
    };
    let process = value(syscall::CREATE_PROCESS, caps.job, image, 0);
    require(process != 0, 474);
    value(syscall::DELEGATE, process, caps.buffer, 1);
    value(syscall::DELEGATE, process, caps.event_tx, 2);
    require(
        rt::call(syscall::PROCESS_IDENTITY, process, 0, 0).status != 0,
        475,
    );
    value(syscall::START, process, 0, 0);
    let id = identity(process);
    require(id.process != own, 476);
    let admitted = admission(catalogue, plan, id);
    request(store, ev_store::Request::Admission(admitted), deadline);
    negatives += spoof(caps, Some(id), own, &mut seen, stop);
    require(negatives == 4, 477);
    let mut stale = admitted;
    stale.process_stamp[0] ^= 0x80;
    reject_health(store, stale, storage_probe, deadline);
    let mut progress = ev_block_service::critical_progress::Window::new(stop);
    let mut outcome = loop {
        // Bound each drain so a foreign event stream cannot starve lifecycle
        // observation or the finite progress deadline.
        for _ in 0..8 {
            if receive(caps, Some(id), own, &mut seen).is_none() {
                break;
            }
        }
        let state = value(syscall::OBSERVE, process, 0, 0);
        require(state <= 1, 479);
        if state == 1 {
            require(
                value(syscall::OBSERVE, process, 1, 0) == id.process
                    && value(syscall::OBSERVE, process, 2, 0) == id.thread,
                480,
            );
            require(
                value(syscall::OBSERVE, process, 3, 0) == 14
                    && value(syscall::OBSERVE, process, 4, 0) == 7,
                481,
            );
            require(
                value(syscall::OBSERVE, process, 5, 0) != 0
                    && value(syscall::OBSERVE, process, 6, 0) != 0,
                482,
            );
            break HealthOutcome::ProcessFault;
        }
        // A live peer which never reports authenticated critical readiness is
        // a durable MissingProgress failure, not an exit of this controller and
        // not a fabricated hardware exception. Only actual LIVE observations
        // advance the finite64tick initialization window.
        match progress
            .observe_live(now(), seen.critical)
            .unwrap_or_else(|_| rt::exit(478))
        {
            ev_block_service::critical_progress::Decision::Ready => {
                require(seen.generic, 483);
                break HealthOutcome::CriticalPassed;
            }
            ev_block_service::critical_progress::Decision::MissingProgress => {
                break HealthOutcome::MissingProgress;
            }
            ev_block_service::critical_progress::Decision::Waiting => (),
        }
        yield_now();
    };
    let storage_probe = if outcome == HealthOutcome::CriticalPassed {
        probe(store, expected, deadline)
    } else {
        payload(store, expected, deadline)
    };
    // Durable probing yields to the actual supervisor. Recheck its lifecycle
    // after that work before persisting a successful health transition.
    if outcome != HealthOutcome::ProcessFault && value(syscall::OBSERVE, process, 0, 0) == 1 {
        require(
            value(syscall::OBSERVE, process, 1, 0) == id.process
                && value(syscall::OBSERVE, process, 2, 0) == id.thread,
            508,
        );
        require(value(syscall::OBSERVE, process, 3, 0) != 0, 509);
        outcome = HealthOutcome::ProcessFault;
    }
    request(
        store,
        ev_store::Request::Health(HealthReport {
            admitted,
            outcome,
            observed_checks: if outcome == HealthOutcome::CriticalPassed {
                3
            } else {
                0
            },
            storage_probe,
        }),
        deadline,
    );
    if outcome != HealthOutcome::ProcessFault {
        value(syscall::STOP_PROCESS, process, 0, 0);
        require(value(syscall::OBSERVE, process, 0, 0) == 1, 485);
    }
    let still = identity(process);
    require(
        still.process == id.process && still.thread == id.thread,
        486,
    );
    value(syscall::REAP, process, 0, 0);
    value(syscall::CLOSE, process, 0, 0);
    require(rt::call(syscall::OBSERVE, process, 0, 0).status != 0, 487);
    Booted {
        plan,
        id,
        stamp: admitted.process_stamp,
        negatives,
        probe: storage_probe,
        outcome,
    }
}
fn failure_reason(failure: LastFailure) -> u64 {
    match failure.reason {
        LastFailureReason::ProcessFault => 1,
        LastFailureReason::MissingProgress => 2,
        LastFailureReason::StorageFailure => 3,
        LastFailureReason::AttemptBudgetExhausted => 4,
        LastFailureReason::CriticalComponentFault => 5,
    }
}
#[cfg(feature = "test-owner-client")]
#[inline(never)]
fn owner_choice(
    store: &mut Store<Device>,
    uart: u64,
    catalogue: Catalogue,
    catalogue_hash: Digest,
    control: Control,
    stop: u64,
    deadline: u64,
) -> OwnerDecision {
    use ev_block_service::owner_console::{Console, Error, KernelIo, Prompt};
    let failure = store
        .last_failure()
        .unwrap_or_else(|e| failed(511, e))
        .unwrap_or_else(|| rt::exit(512));
    let selected = store
        .selected_manifest(deadline)
        .unwrap_or_else(|e| failed(513, e));
    let known_good = store.known_good().unwrap_or_else(|| rt::exit(514));
    require(
        selected == manifest(catalogue, Slot::B, 3)
            && known_good == GenerationId::new(1).unwrap()
            && failure.generation == GenerationId::new(2).unwrap()
            && failure.reason == LastFailureReason::ProcessFault
            && failure.supervisor_image == catalogue.image_b,
        515,
    );
    let operation = store
        .next_operation()
        .unwrap_or_else(|e| failed(516, e))
        .get()
        - 1;
    let mut console = Console::new(KernelIo { capability: uart });
    match console.choose(Prompt {
        failed: &failure,
        selected: selected.generation,
        known_good,
        build: catalogue.kernel_build,
        catalogue: catalogue_hash,
        operation,
        prompt_ticks: control.prompt_ticks,
        world_stop: stop,
    }) {
        Ok(outcome) => {
            require(
                match outcome.decision {
                    OwnerDecision::Continue => matches!(outcome.source_byte, Some(b'r' | b'R')),
                    OwnerDecision::Cancel => matches!(outcome.source_byte, Some(b'q' | b'Q')),
                    _ => outcome.source_byte.is_none(),
                },
                517,
            );
            outcome.decision
        }
        Err(Error::Deadline) => OwnerDecision::Timeout,
        Err(Error::PollBudget) => OwnerDecision::InputBudget,
        Err(_) => OwnerDecision::InputFault,
    }
}
#[inline(never)]
pub(super) fn run(bytes: &[u8], record: u64, stop: u64) -> ! {
    #[cfg(feature = "test-owner-client")]
    let owner = ev_block_service::owner_startup(bytes).unwrap_or_else(|_| rt::exit(488));
    #[cfg(feature = "test-owner-client")]
    let caps = owner.generation;
    #[cfg(not(feature = "test-owner-client"))]
    let caps = ev_block_service::generation_startup(bytes).unwrap_or_else(|_| rt::exit(488));
    let own = Bootstrap::parse(bytes)
        .unwrap_or_else(|_| rt::exit(489))
        .process();
    let (catalogue, catalogue_hash) = catalogue(record);
    // Every complete component mismatch must fail resolution before lifecycle
    // calls. Candidate3 deliberately reuses B components with a fresh sequence.
    let good = manifest(catalogue, Slot::A, 1);
    let mut wrong = good;
    wrong.cohort[0] ^= 1;
    require(resolve(catalogue, &wrong).is_none(), 490);
    wrong = good;
    wrong.abi[0] ^= 1;
    require(resolve(catalogue, &wrong).is_none(), 491);
    require(
        resolve(catalogue, &manifest(catalogue, Slot::B, 3)) == Some(Slot::B),
        492,
    );
    let window = Window::new(record);
    window.guards();
    let deadline = stop.checked_add(512).unwrap_or_else(|| rt::exit(493));
    require(now() < stop, 494);
    let mut endpoint = Endpoint(SyncEndpoint {
        endpoint: caps.block,
    });
    let control = control(&mut endpoint, &window, deadline);
    #[cfg(feature = "test-owner-client")]
    require(control.mode != Mode::ManualA, 518); // Owner rollback requires real UART consent.
    #[cfg(not(feature = "test-owner-client"))]
    require(
        !matches!(control.mode, Mode::OwnerPrepare3 | Mode::OwnerRecover),
        518,
    );
    let device = StoreRegion::new(endpoint, window, stop).unwrap_or_else(|| rt::exit(495));
    #[cfg(feature = "test-owner-client")]
    let device = {
        let mut gate = ev_block_service::store_io::WriteGate::closed(device);
        if control.mode != Mode::OwnerRecover {
            gate.allow_writes();
        }
        gate
    };
    let mut store = if control.mode == Mode::ProvisionA {
        format(device, catalogue, deadline)
    } else {
        open(device, deadline)
    };
    let expected = if control.mode == Mode::ProvisionA {
        OWNER_A
    } else {
        OWNER_B
    };
    if control.mode == Mode::FailB {
        payload(&mut store, OWNER_A, deadline);
        require(store.known_good() == GenerationId::new(1), 496);
        probe(&mut store, OWNER_B, deadline);
        request(
            &mut store,
            ev_store::Request::Stage(&manifest(catalogue, Slot::B, 2)),
            deadline,
        );
        request(
            &mut store,
            ev_store::Request::Activate(GenerationId::new(2).unwrap()),
            deadline,
        );
    } else if matches!(control.mode, Mode::ManualA | Mode::OwnerPrepare3) {
        payload(&mut store, OWNER_B, deadline);
        require(
            store
                .highest_generation()
                .unwrap_or_else(|e| failed(519, e))
                == 2,
            520,
        );
        request(
            &mut store,
            ev_store::Request::Stage(&manifest(catalogue, Slot::B, 3)),
            deadline,
        );
        request(
            &mut store,
            ev_store::Request::Activate(GenerationId::new(3).unwrap()),
            deadline,
        );
        if control.mode == Mode::ManualA {
            request(&mut store, ev_store::Request::SelectKnownGood, deadline);
        }
    }
    #[cfg(feature = "test-owner-client")]
    let owner_decision = if control.mode == Mode::OwnerRecover {
        owner_choice(
            &mut store,
            owner.uart,
            catalogue,
            catalogue_hash,
            control,
            stop,
            deadline,
        )
    } else {
        OwnerDecision::None
    };
    #[cfg(not(feature = "test-owner-client"))]
    let owner_decision = OwnerDecision::None;
    #[cfg(feature = "test-owner-client")]
    if owner_decision == OwnerDecision::Continue {
        let mut device = store.into_device();
        device.allow_writes();
        store = open(device, deadline);
        request(&mut store, ev_store::Request::SelectKnownGood, deadline);
    }
    let no_action = control.mode == Mode::OwnerRecover && owner_decision != OwnerDecision::Continue;
    let prepared = control.mode == Mode::OwnerPrepare3 || no_action;
    let booted = if control.mode == Mode::Verify || prepared {
        None
    } else {
        Some(boot(
            &mut store, catalogue, caps, own, expected, deadline, stop,
        ))
    };
    if let Some(booted) = booted {
        require(
            (booted.outcome != HealthOutcome::CriticalPassed) == (control.mode == Mode::FailB),
            497,
        );
    }
    let selected = store
        .selected_manifest(deadline)
        .unwrap_or_else(|e| failed(498, e));
    require(
        selected
            == if prepared {
                manifest(catalogue, Slot::B, 3)
            } else {
                manifest(catalogue, Slot::A, 1)
            }
            && store.known_good() == GenerationId::new(1),
        499,
    );
    let storage_probe = payload(&mut store, expected, deadline);
    let failure = store.last_failure().unwrap_or_else(|e| failed(500, e));
    if control.mode == Mode::ProvisionA {
        require(failure.is_none(), 501);
    } else {
        let failed = failure.unwrap_or_else(|| rt::exit(502));
        require(
            failed.generation == GenerationId::new(2).unwrap()
                && failed.supervisor_image == catalogue.image_b
                && matches!(
                    failed.reason,
                    LastFailureReason::ProcessFault | LastFailureReason::MissingProgress
                )
                && failed.process_stamp.is_some(),
            503,
        );
        if let Some(current) = booted
            && current.outcome != HealthOutcome::CriticalPassed
        {
            require(
                failed.boot_serial == current.plan.serial
                    && failed.process_stamp == Some(current.stamp)
                    && failed.reason
                        == if current.outcome == HealthOutcome::ProcessFault {
                            LastFailureReason::ProcessFault
                        } else {
                            LastFailureReason::MissingProgress
                        },
                504,
            );
        }
    }
    let next = store
        .next_operation()
        .unwrap_or_else(|e| failed(505, e))
        .get();
    let device = store.into_device();
    #[cfg(feature = "test-owner-client")]
    let device = device.into_inner();
    let mutations = device.mutations();
    let (_, window) = device.into_parts();
    let report = Completion {
        mode: control.mode,
        owner_decision,
        booted: booted.map_or(0, |b| b.plan.manifest.generation.get()),
        selected: selected.generation.get(),
        known_good: 1,
        boot_serial: booted.map_or(0, |b| b.plan.serial),
        process: booted.map_or(0, |b| b.id.process),
        thread: booted.map_or(0, |b| b.id.thread),
        failure_generation: failure.map_or(0, |f| f.generation.get()),
        failure_serial: failure.map_or(0, |f| f.boot_serial),
        failure_reason: failure.map_or(0, failure_reason),
        negatives: booted.map_or(0, |b| b.negatives),
        mutations,
        operation: next - 1,
        sequence: next,
        failure_operation: failure.map_or(0, |f| f.operation.get()),
        failure_sequence: failure.map_or(0, |f| f.sequence),
        catalogue: catalogue_hash,
        process_stamp: booted.map_or([0; 32], |b| b.stamp),
        storage_probe,
        booted_cohort: booted.map_or([0; 32], |b| b.plan.manifest.cohort),
    };
    if let Some(booted) = booted {
        require(booted.probe == storage_probe, 506);
    }
    let encoded = report.encode();
    require(Completion::decode(&encoded) == Ok(report), 507);
    window.guards();
    window.publish(&encoded);
    window.guards();
    rt::exit(0)
}
