//! Isolated development userspace PIO execution; not a device-bearing BAC fence.
use crate::{
    executable_runtime::{LoadedImage, ProcessImage},
    supervisor_runtime::bundle,
};
use core::{arch::asm, num::NonZeroU64};
use ev_kernel::{
    capability::{Authority, Kind, Rights},
    io_ports::{Caller, Direction, Range, Registry as Ports, Request, Widths},
    mapping::ADDRESS_MASK,
    memory::BootstrapFrames,
    rpc::Rpc,
    scheduler::{Limits, Resource, Scheduler},
    service::{Registry, Role, ServiceImage},
    time::Deadline,
    user_context::{Call, FxState, decode},
};

const LIMITS: Limits = Limits::new(1024, 32, 1, 1);
const ATA: [Range; 3] = [
    Range {
        first: 0x1e8,
        last: 0x1e9,
        widths: Widths::WORD,
        direction: Direction::Both,
    },
    Range {
        first: 0x1e9,
        last: 0x1ef,
        widths: Widths::BYTE,
        direction: Direction::Both,
    },
    Range {
        first: 0x3ee,
        last: 0x3ee,
        widths: Widths::BYTE,
        direction: Direction::Both,
    },
];
#[derive(Default)]
pub struct Proof {
    pub inputs: u64,
    pub outputs: u64,
    pub denied: u64,
    pub malformed: u64,
    pub direct_denied: u64,
    pub exits: u64,
    pub frames: bool,
    pub metadata: bool,
}
fn result(frame: &mut ev_kernel::user_context::UserContext, status: u64, value: u64) {
    let port_abi = matches!(
        frame.registers[14],
        ev_userspace_contract::syscall::PORT_INPUT | ev_userspace_contract::syscall::PORT_OUTPUT
    );
    frame.registers[14] = status;
    frame.registers[9] = value;
    frame.registers[11] = 0;
    // Only the four-operand port ABI declares R10 as an output. Legacy clock
    // and yield wrappers may keep live values there across the trap.
    if port_abi {
        frame.registers[5] = 0;
    }
}
/// # Safety
/// Serialized BSP IF=0, AP parked, retained controller/direct map, initialized
/// user/FX/PIC boundary, exclusive allocator; dedicated non-DMA test controller.
#[inline(never)]
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) -> Proof {
    // Direct IN faults in an independent process before any accepted command.
    // SAFETY: every case stops and fully retires its process before returning.
    let fault = unsafe { run(offset, frames, true) };
    // SAFETY: prior case restored controller root and all allocator ownership.
    let mut proof = unsafe { run(offset, frames, false) };
    assert_eq!(fault.direct_denied, 1);
    assert_eq!((fault.inputs, fault.outputs), (0, 0));
    proof.direct_denied += fault.direct_denied;
    proof.frames &= fault.frames;
    proof.metadata &= fault.metadata;
    proof
}
#[inline(never)]
unsafe fn run(offset: u64, frames: &mut BootstrapFrames, direct: bool) -> Proof {
    let before = frames.remaining_frames();
    let original: u64;
    // SAFETY: privileged read, no user process active.
    unsafe { asm!("mov {}, cr3", out(reg) original, options(nomem, nostack, preserves_flags)) };
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8;
    let epoch = NonZeroU64::new(if direct { 251 } else { 252 }).unwrap();
    let mut a = Authority::new();
    let custody = a.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let job_cap = a
        .create_root(custody, Kind::Job, common | Rights::READ | Rights::CONTROL)
        .unwrap();
    let image_cap = a.create_root(custody, Kind::Memory, Rights::READ).unwrap();
    let port_cap = a
        .create_root(
            custody,
            Kind::IoPorts,
            common | Rights::READ | Rights::WRITE | Rights::CONTROL,
        )
        .unwrap();
    let mut ports = Ports::new();
    ports.register(&a, custody, port_cap, &ATA).unwrap();
    let mut s = Scheduler::new();
    let job = s.create_job_with_limits(LIMITS).unwrap();
    let mut registry = Registry::with_service_limits(NonZeroU64::new(1).unwrap(), LIMITS).unwrap();
    registry.register_job(&a, custody, job_cap, job).unwrap();
    let (bytes, sha) = if direct {
        (bundle::M3_PIO_DIRECT_IMAGE, bundle::M3_PIO_DIRECT_SHA)
    } else if cfg!(feature = "test-m3-pio-write") {
        (bundle::M3_PIO_WRITE_IMAGE, bundle::M3_PIO_WRITE_SHA)
    } else {
        (bundle::M3_PIO_VERIFY_IMAGE, bundle::M3_PIO_VERIFY_SHA)
    };
    let roles = [
        Role {
            selector: 1,
            kind: Kind::IoPorts,
            rights: Rights::from_bits(3).unwrap(),
        },
        Role {
            selector: 2,
            kind: Kind::IoPorts,
            rights: Rights::READ,
        },
    ];
    registry
        .register_image(
            &a,
            custody,
            image_cap,
            ServiceImage::verify(bytes, sha, LIMITS, &roles).unwrap(),
        )
        .unwrap();
    let control = registry
        .create_process(&mut a, &mut s, custody, job_cap, image_cap)
        .unwrap();
    for role in roles {
        registry
            .delegate(&mut a, custody, control, port_cap, role.selector)
            .unwrap();
    }
    let meta = registry.metadata(&a, custody, control).unwrap();
    let startup = registry.startup(&a, custody, control, epoch).unwrap();
    let plan = registry.plan(&a, custody, control).unwrap();
    // SAFETY: actual measured held process; exclusive inactive backing.
    let mut loaded = unsafe {
        LoadedImage::load_startup(
            offset,
            bits,
            original & ADDRESS_MASK,
            &plan,
            Some(&startup),
            frames,
        )
    }
    .unwrap();
    let mut active = registry
        .start(
            &a,
            &mut s,
            custody,
            control,
            epoch,
            ProcessImage {
                loaded: &mut loaded,
                process: meta.process,
                frames: meta.frames,
            },
        )
        .unwrap_or_else(|r| panic!("block admission: {:?}", r.error));
    let mut context = active.initial_context().unwrap();
    let mut fx = FxState::CLEAN;
    let mut rpc = Rpc::new(epoch);
    rpc.register_thread(&a, &s, meta.thread, meta.job, meta.domain, None)
        .unwrap();
    let global = Deadline::after(crate::timer::now(), 1024).unwrap();
    let mut proof = Proof::default();
    let mut done = false;
    // SAFETY: exclusive runtime PIC owner; each IRET enables finite timer slices.
    unsafe { crate::timer::start_runtime() };
    for _ in 0..100_000 {
        assert!(!global.reached(crate::timer::now()), "block actor deadline");
        let dispatch = s.dispatch(0).unwrap().expect("block runnable");
        assert_eq!(
            (dispatch.process, dispatch.thread),
            (meta.process, meta.thread)
        );
        active.image().loaded.root.activate();
        // SAFETY: exclusively admitted actual root/context/FX; trap restores CR3.
        let (mut frame, address) =
            unsafe { crate::user_runtime::resume_context(&context, &mut fx, original) };
        match frame.vector {
            32 => s.charge_cpu(0, 1).expect("block CPU quota"),
            128 => {
                let caller = Caller {
                    authority: &a,
                    scheduler: &s,
                    rpc: &rpc,
                    cpu: 0,
                };
                match decode(&frame) {
                    Ok(Call::PortInput {
                        capability,
                        port,
                        width,
                    }) => {
                        match ports.input(
                            caller,
                            Request {
                                capability,
                                port,
                                width,
                            },
                        ) {
                            Ok(permit) => {
                                // SAFETY: consumed permit borrows live authority,
                                // exact immutable binding and actual caller.
                                let value = unsafe { crate::port_io::input(permit) };
                                proof.inputs += 1;
                                result(&mut frame, 0, u64::from(value));
                            }
                            Err(_) => {
                                proof.denied += 1;
                                result(&mut frame, 1, 0);
                            }
                        }
                    }
                    Ok(Call::PortOutput {
                        capability,
                        port,
                        width,
                        value,
                    }) => {
                        match ports.output(
                            caller,
                            Request {
                                capability,
                                port,
                                width,
                            },
                            value,
                        ) {
                            Ok(permit) => {
                                // SAFETY: same single-instruction permit contract.
                                unsafe { crate::port_io::output(permit) };
                                proof.outputs += 1;
                                result(&mut frame, 0, 0);
                            }
                            Err(_) => {
                                proof.denied += 1;
                                result(&mut frame, 1, 0);
                            }
                        }
                    }
                    Ok(Call::Monotonic) => result(&mut frame, 0, crate::timer::now()),
                    Ok(Call::Yield) => result(&mut frame, 0, 0),
                    Ok(Call::Exit(code)) => {
                        assert!(!direct, "direct port instruction did not fault");
                        assert_eq!(code, 0, "userspace block failure");
                        proof.exits += 1;
                        done = true;
                    }
                    Err(_) => {
                        proof.malformed += 1;
                        result(&mut frame, 3, 0);
                    }
                    _ => result(&mut frame, 1, 0),
                }
            }
            _ => {
                assert!(
                    direct && frame.ordinary_user_fault(),
                    "unexpected block fault vector={} error={} address={:#x}",
                    frame.vector,
                    frame.error,
                    address
                );
                assert_eq!((frame.vector, frame.error), (13, 0));
                assert_eq!(frame.registers[11] & 0xffff, 0x1e8, "actual direct-IN port");
                proof.direct_denied += 1;
                done = true;
            }
        }
        context = frame;
        s.yield_cpu(0).unwrap();
        if done {
            break;
        }
    }
    // SAFETY: controller root/IF0 restored; no process executing.
    unsafe { crate::timer::stop_runtime() };
    assert!(done, "block actor transition bound");
    if !direct {
        assert_eq!((proof.denied, proof.malformed, proof.exits), (4, 4, 1));
        assert!(proof.inputs >= 256 * 3 && proof.outputs >= 10);
    }
    active.stop(&mut a, &mut s).unwrap();
    s.terminate_process(meta.process).unwrap();
    assert!(
        rpc.peer_died(&s, meta.thread, crate::timer::now())
            .unwrap()
            .is_empty()
    );
    let ProcessImage { loaded, .. } = active
        .finish(&s)
        .unwrap_or_else(|_| panic!("block retained image"));
    // SAFETY: source-built direct probe accepted no commands; normal actor has
    // completed bounded status drain and its selected flush/readback protocol.
    // No DMA, mapped device memory, queued RPC or AP references exist. This
    // narrow world is NOT a reusable device-bearing Root restart receipt.
    unsafe { assert_eq!(loaded.root.retire_in_place(frames) as u64, meta.frames) };
    s.release_frames(meta.job, meta.frames).unwrap();
    registry.retire_stopped(&mut a, &s, meta.process).unwrap();
    a.close(custody, control).unwrap();
    registry.forget_retired(&mut a, &s, meta.process).unwrap();
    rpc.forget_thread(&s, meta.thread).unwrap();
    s.reclaim_process(meta.process).unwrap();
    ports.retire(&mut a, custody, port_cap).unwrap();
    registry.forget_job(&mut a, &mut s, &rpc, job).unwrap();
    a.collect_lineage().unwrap();
    assert_eq!(a.metadata_usage(), (1, 2, 2, 2));
    assert_eq!(registry.metadata_usage(), (0, 1, 0, 2));
    assert_eq!(s.metadata_usage(), (0, 0, 0));
    assert_eq!(rpc.metadata_usage(), (0, 0, 0));
    assert_eq!(ports.registered(), 0);
    assert_eq!(frames.remaining_frames(), before);
    for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
        assert!(s.usage(job, resource).is_err());
    }
    proof.frames = true;
    proof.metadata = true;
    proof
}
