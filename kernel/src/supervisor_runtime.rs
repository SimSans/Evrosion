//! First source-built Root Supervisor startup, using the ordinary CPL3 boundary.
//! Development acceptance only: no sealed BAC, replacement or service graph yet.
use crate::executable_runtime::{LoadedImage, ProcessImage};
use core::{arch::asm, num::NonZeroU64};
use ev_kernel::{
    bootstrap_binding::CatalogEntry,
    bootstrap_manifest,
    capability::{Authority, Kind, Rights},
    fault::Record,
    incarnation::{Bindings, Phase, Target},
    ipc::{Mailbox, Outgoing},
    mapping::ADDRESS_MASK,
    memory::BootstrapFrames,
    scheduler::{Resource, Scheduler},
    time::Deadline,
    user_context::{Call, FxState, decode},
};
use ev_userspace_contract::{ABI, Event, SIZE};

pub(crate) mod bundle {
    include!(concat!(env!("OUT_DIR"), "/supervisor-bundle.rs"));
}

/// # Safety
/// Serialized BSP, IF=0, AP parked, retained direct map and exclusive frames;
/// initialized ordinary user trap/FX/PIC boundary. No user process is active.
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) {
    // Missing bundle in direct lint builds must never produce runtime PASS.
    assert!(!bundle::NORMAL_IMAGE.is_empty() && !bundle::FAULT_IMAGE.is_empty());
    assert_ne!(bundle::NORMAL_MEASUREMENT, bundle::FAULT_MEASUREMENT);
    for (image, manifest, measurement, fault) in [
        (
            bundle::NORMAL_IMAGE,
            bundle::NORMAL_MANIFEST,
            bundle::NORMAL_MEASUREMENT,
            false,
        ),
        (
            bundle::FAULT_IMAGE,
            bundle::FAULT_MANIFEST,
            bundle::FAULT_MEASUREMENT,
            true,
        ),
    ] {
        // SAFETY: each case owns its independent tables and returns all frames
        // with the original root restored before the next case can execute.
        unsafe { run(offset, frames, image, manifest, measurement, fault) };
    }
}

/// # Safety
/// Same as prove. This case retains all backing until execution and leases end.
unsafe fn run(
    offset: u64,
    frames: &mut BootstrapFrames,
    executable: &[u8],
    bytes: &[u8],
    measurement: [u8; 32],
    inject_fault: bool,
) {
    let manifest = bootstrap_manifest::verify(bytes, measurement, executable, ABI).unwrap();
    let mut authority = Authority::new();
    let custody = authority.create_space().unwrap();
    let branches = authority.create_space().unwrap();
    let destination = authority.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let memory = authority
        .create_root(custody, Kind::Memory, common | Rights::READ)
        .unwrap();
    let endpoint = authority
        .create_root(
            custody,
            Kind::Endpoint,
            common | Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
        )
        .unwrap();
    let catalog = [
        CatalogEntry {
            selector: 1,
            root: memory,
            kind: Kind::Memory,
        },
        CatalogEntry {
            selector: 2,
            root: endpoint,
            kind: Kind::Endpoint,
        },
    ];
    let mut mailbox = Mailbox::new(&mut authority, custody, endpoint).unwrap();
    let mut scheduler = Scheduler::new();
    let job = scheduler.create_job_with_limits(manifest.limits()).unwrap();
    let process = scheduler.create_held_process(job).unwrap();
    let thread = scheduler.create_thread(process).unwrap();
    let target = Target {
        process,
        job,
        branches,
        destination,
    };
    // Isolated development epoch. Production boot-epoch generation is not
    // inferred from this acceptance controller's deterministic value.
    let mut binding = Bindings::new(NonZeroU64::new(101).unwrap(), &manifest, custody, &catalog);
    let token = binding.prepare(&mut authority, &scheduler, target).unwrap();
    let startup = binding.bootstrap_record(token).unwrap().unwrap();
    let image = binding.executable(token).unwrap();
    let startup_address = image.bootstrap_page().unwrap();
    scheduler
        .charge_frames(job, image.required_frames())
        .unwrap();
    let original: u64;
    // SAFETY: privileged read only, retained controller root, no competing entry.
    unsafe { asm!("mov {}, cr3",out(reg) original,options(nomem,nostack,preserves_flags)) };
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8;
    let before = frames.remaining_frames();
    // SAFETY: inactive private root, exclusive allocator; startup is derived from
    // this exact held token and HAL verifies final read-only/NX bytes.
    let mut loaded = unsafe {
        LoadedImage::load_startup(
            offset,
            bits,
            original & ADDRESS_MASK,
            &image,
            Some(&startup),
            frames,
        )
    }
    .unwrap();
    assert_eq!(before - frames.remaining_frames(), image.required_frames());
    {
        let lease = ProcessImage {
            loaded: &mut loaded,
            process,
            frames: image.required_frames(),
        };
        assert_eq!(scheduler.dispatch(0), Ok(None));
        let mut active = binding
            .activate(&authority, &mut scheduler, token, thread, lease)
            .unwrap_or_else(|r| panic!("supervisor activation: {:?}", r.error));
        let mut context = active.initial_context().unwrap();
        assert_eq!(context.registers[8], startup_address);
        assert_eq!(context.registers[9], SIZE as u64);
        let mut fx = FxState::CLEAN;
        let mut ready = 0;
        let mut read = 0;
        let mut denied = 0;
        let mut yields = 0;
        let mut fault_record = None;
        let deadline = Deadline::after(crate::timer::now(), 100).unwrap();
        let mut stopped = false;
        // SAFETY: exclusive initialized PIC owner at IF=0. User IRET enables
        // timer IRQs, so even a broken userspace loop returns to this controller.
        unsafe { crate::timer::start_runtime() };
        for _ in 0..256 {
            assert!(
                !deadline.reached(crate::timer::now()),
                "supervisor startup deadline"
            );
            let dispatch = scheduler.dispatch(0).unwrap().unwrap();
            assert_eq!(dispatch.process, process);
            assert_eq!(dispatch.thread, thread);
            active.image().loaded.root.activate();
            // SAFETY: exclusively owned admitted root/context and FX state,
            // ordinary trap runner restores controller CR3 before returning.
            let (mut frame, address) =
                unsafe { crate::user_runtime::resume_context(&context, &mut fx, original) };
            match frame.vector {
                32 => scheduler.charge_cpu(0, 1).expect("supervisor CPU budget"),
                128 => {
                    frame.registers[14] = match decode(&frame) {
                        Ok(Call::Inspect { capability, rights }) => {
                            if authority
                                .authorize(destination, capability, Kind::Memory, rights)
                                .is_ok()
                            {
                                read += 1;
                                0
                            } else {
                                denied += 1;
                                1
                            }
                        }
                        Ok(Call::Send {
                            endpoint: send,
                            value,
                            capability: None,
                        }) => {
                            let payload = value.to_le_bytes();
                            mailbox
                                .send(
                                    &mut authority,
                                    destination,
                                    send,
                                    Outgoing {
                                        bytes: &payload,
                                        capability: None,
                                        deadline,
                                    },
                                    crate::timer::now(),
                                )
                                .expect("supervisor event send");
                            let delivery = mailbox
                                .receive(&mut authority, custody, endpoint, crate::timer::now())
                                .expect("kernel bootstrap event receive");
                            assert_eq!(delivery.capability, None);
                            assert_eq!(
                                Event::decode(&delivery.bytes[..delivery.length]),
                                Some(Event::Ready)
                            );
                            ready += 1;
                            assert_eq!(ready, 1);
                            0
                        }
                        Ok(Call::Yield) => {
                            assert!(!inject_fault);
                            assert_eq!(ready, 1);
                            yields += 1;
                            stopped = yields == 2;
                            0
                        }
                        Ok(Call::Exit(code)) => panic!("supervisor startup exit {code}"),
                        _ => 3,
                    };
                }
                _ => {
                    assert!(inject_fault && frame.ordinary_user_fault());
                    assert_eq!(ready, 1);
                    assert_eq!(
                        (frame.vector, frame.error, address),
                        (14, 7, startup_address)
                    );
                    let record = Record {
                        process: process.diagnostic_id(),
                        thread: thread.diagnostic_id(),
                        vector: frame.vector,
                        error: frame.error,
                        address,
                        instruction: frame.rip,
                    };
                    assert_eq!(Record::decode(&record.encode()), Some(record));
                    fault_record = Some(record);
                    stopped = true;
                }
            }
            if stopped {
                // The actual fault (or normal acceptance stop) inhibits dispatch
                // and revokes the whole incarnation before process retirement.
                active
                    .revoke(&mut authority, &mut scheduler, token)
                    .unwrap();
                assert_eq!(scheduler.exit(0), Ok(thread));
                scheduler.terminate_process(process).unwrap();
                break;
            }
            context = frame;
            scheduler.yield_cpu(0).unwrap();
        }
        // SAFETY: capture returned at IF=0 with controller CR3 restored. No user
        // can run while timer/authority/scheduler state and backing are retired.
        unsafe { crate::timer::stop_runtime() };
        assert!(stopped, "supervisor exceeded finite trap bound");
        assert_eq!((ready, read, denied), (1, 1, 2));
        assert_eq!(fault_record.is_some(), inject_fault);
        assert_eq!(yields, if inject_fault { 0 } else { 2 });
        assert_eq!(scheduler.dispatch(0), Ok(None));
        let (binding, _lease) = active
            .finish(&scheduler, token)
            .unwrap_or_else(|_| panic!("supervisor remained active after stop"));
        assert_eq!(binding.phase(), Phase::Revoked);
    }
    mailbox.receiver_died(custody).unwrap();
    assert_eq!(mailbox.pending(), 0);
    mailbox.retire_empty(&mut authority).unwrap();
    authority.close_space(destination).unwrap();
    authority.close_space(branches).unwrap();
    assert!(
        authority
            .authorize(custody, memory, Kind::Memory, Rights::READ)
            .is_ok()
    );
    assert!(
        authority
            .authorize(custody, endpoint, Kind::Endpoint, Rights::RECEIVE)
            .is_ok()
    );
    // SAFETY: stopped/retired process, original CR3 current, AP parked, mailbox
    // empty, all image leases ended. No DMA/device mapping was ever granted.
    unsafe { assert_eq!(loaded.root.retire(frames) as u64, image.required_frames()) };
    scheduler
        .release_frames(job, image.required_frames())
        .unwrap();
    for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
        assert_eq!(scheduler.usage(job, resource), Ok(0));
    }
    assert_eq!(frames.remaining_frames(), before);
}
