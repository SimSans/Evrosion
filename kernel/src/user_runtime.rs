//! Serialized BSP userspace scheduler. Every user trap returns to the controller;
//! no suspended kernel stack is shared between processes. Quiescent frames recycle.
use crate::user_space::UserRoot;
use core::{
    arch::{asm, global_asm},
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
use ev_kernel::{
    allocation::{Anonymous, Domain as AllocationDomain},
    capability::{Authority, Handle, Kind, Rights},
    fault::Record as FaultRecord,
    ipc::{Delivery, Error as IpcError, Mailbox, Outgoing, Reclaimed, Ticket},
    mapping::{ADDRESS_MASK, direct_address},
    memory::{BootstrapFrames, FRAME_SIZE},
    memory_object::MemoryObject,
    scheduler::{Limits, Resource, Scheduler, State, WakeReason},
    time::Deadline,
    user::UserPermission,
    user_context::{Call, FxState, UserContext, decode},
    wait_queue::WaitQueue,
};
// SAFETY: saved GP context layout is asserted by the portable type; IRET uses
// validated CPL3 selectors/flags and retained private user mappings.
global_asm!(include_str!("user_runtime.S"));
unsafe extern "C" {
    fn ev_resume_user(frame: *const UserContext, fx: *mut FxState);
    static ev_runtime_blob: u8;
    static ev_runtime_blob_end: u8;
    static ev_runtime_good: u8;
    static ev_runtime_bad: u8;
    static ev_runtime_revoked_read: u8;
}
// SAFETY: assembly symbols are unique, BSP-only, and accessed with IF=0.
#[unsafe(no_mangle)]
static mut ev_active_fx: u64 = 0;
// SAFETY: unique assembly symbol with the 16-byte aligned FXSAVE layout.
#[unsafe(no_mangle)]
static mut ev_kernel_fx: FxState = FxState::CLEAN;
static ACTIVE: AtomicBool = AtomicBool::new(false);
static CAPTURED: AtomicBool = AtomicBool::new(false);
static mut SAVED: UserContext = UserContext::ZERO;
static mut ADDRESS: u64 = 0;
pub(crate) fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}
pub(crate) fn capture(frame: &UserContext, address: u64) -> bool {
    if !active()
        || frame.cs & 3 != 3
        || !(matches!(frame.vector, 32 | 128) || frame.ordinary_user_fault())
    {
        return false;
    }
    if CAPTURED.swap(true, Ordering::Relaxed) {
        crate::finish(false);
    }
    // SAFETY: BSP with IF=0 in the owned trap handler. Controller is suspended,
    // no borrow of these slots exists, and the frame belongs to ENTRY_STACK.
    unsafe {
        ptr::addr_of_mut!(SAVED).write(*frame);
        ptr::addr_of_mut!(ADDRESS).write(address);
    }
    true
}
#[derive(Clone, Copy)]
struct Fault {
    vector: u64,
    error: u64,
    address: u64,
}
pub struct Proof {
    pub faults: u64,
    pub survivors: u64,
    pub quanta: u64,
    pub messages: u64,
    pub blocks: u64,
    pub signals: u64,
    pub deadlines: u64,
    pub idle_ticks: u64,
    pub terminated: u64,
    pub reclaimed: u64,
    pub discarded: u64,
    pub freed_frames: u64,
    pub reused_frames: u64,
    pub shared_objects: u64,
    pub shared_maps: u64,
    pub denied_maps: u64,
    pub revoked_maps: u64,
    pub revoked_denials: u64,
    pub notifications: u64,
    pub anonymous_allocations: u64,
    pub anonymous_frees: u64,
}
fn deliver(frame: &mut UserContext, delivery: Delivery) {
    assert_eq!(delivery.length, 8);
    frame.registers[9] = u64::from_le_bytes(delivery.bytes[..8].try_into().unwrap());
    frame.registers[11] = delivery.capability.map_or(0, |h| h.0);
}
pub(crate) fn idle_tick() {
    assert!(!active());
    let deadline = Deadline::after(crate::timer::now(), 1).expect("idle deadline");
    #[cfg(feature = "test-user-wait-stall")]
    // SAFETY: the runtime owns the initialized PIC and has IF=0. Mask the clock
    // only in the separately identified idle-failure image.
    unsafe {
        crate::timer::stop_runtime();
    }
    let polls = if cfg!(feature = "test-user-wait-stall") {
        4096
    } else {
        20_000_000
    };
    // SAFETY: BSP, AP parked, no user/handler active; only the initialized timer
    // IRQ is unmasked. The handler changes only its clock. No lock is held.
    // Poll count also bounds a stalled clock; IF is restored before inspection.
    let result = unsafe {
        asm!("sti", options(nostack));
        let result = ev_kernel::time::wait_bounded(deadline, polls, crate::timer::now);
        asm!("cli", options(nostack));
        result
    };
    assert!(
        result.is_ok(),
        "user wait clock stalled within finite idle bound"
    );
}
fn flags() -> u64 {
    let f; /* SAFETY: live controller stack; read flags only. */
    unsafe {
        asm!("pushfq","pop {}",out(reg) f,options(preserves_flags));
    }
    f
}
/// Resume one retained userspace context and return its next trap, with the
/// controller root restored before any scheduler, authority or mapping mutation.
///
/// # Safety
/// Serialized BSP, IF=0, AP parked, initialized TSS/IDT/FX support and timer PIC.
/// The selected root is active and retains every validated context mapping;
/// original is the retained controller CR3. No nested entry or alias of fx.
pub(crate) unsafe fn resume_context(
    context: &UserContext,
    fx: &mut FxState,
    original: u64,
) -> (UserContext, u64) {
    assert!(context.resumable());
    assert_eq!(flags() & (1 << 9), 0);
    CAPTURED.store(false, Ordering::Relaxed);
    assert!(!ACTIVE.swap(true, Ordering::Relaxed));
    #[cfg(feature = "test-runtime-kernel-fault")]
    // SAFETY: deliberate CPL0 #UD while active must remain a fatal kernel fault.
    unsafe {
        asm!("ud2", options(nomem, nostack));
    }
    // SAFETY: caller retains the selected root/context and exclusive FX state.
    // The trap handler writes distinct static slots while this call is suspended.
    unsafe {
        ev_resume_user(context, fx);
    }
    ACTIVE.store(false, Ordering::Relaxed);
    // SAFETY: captured user is stopped, IF=0, retained controller root is live.
    unsafe {
        asm!("mov cr3, {}", in(reg) original, options(nostack,preserves_flags));
    }
    // SAFETY: entry saved user FX state and cleared the active pointer at IF=0.
    assert_eq!(unsafe { ptr::addr_of!(ev_active_fx).read() }, 0);
    assert!(CAPTURED.load(Ordering::Relaxed));
    assert_eq!(flags() & (1 << 9), 0);
    // SAFETY: controller resumed with IF=0; trap handler no longer owns the slots.
    unsafe { (ptr::addr_of!(SAVED).read(), ptr::addr_of!(ADDRESS).read()) }
}
/// # Safety
/// BSP, IF=0, AP parked, retained validated direct map and exclusive frames;
/// owned TSS/IDT and PIC initialized, PCID off. No other user entry is active.
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) -> Proof {
    assert_eq!(flags() & (1 << 9), 0);
    let features = core::arch::x86_64::__cpuid(1).edx;
    assert_eq!(
        features & ((1 << 24) | (1 << 25) | (1 << 26)),
        (1 << 24) | (1 << 25) | (1 << 26),
        "FXSR/SSE2 required"
    );
    // SAFETY: BSP IF=0, before any scheduled user. Enable legacy FPU/SSE,
    // disable unsupported XSAVE/AVX and user-controlled FS/GS bases.
    unsafe {
        let mut cr0: u64;
        let mut cr4: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem,nostack));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem,nostack));
        cr0 = (cr0 & !((1 << 2) | (1 << 3))) | (1 << 1) | (1 << 5);
        cr4 = (cr4 & !((1 << 16) | (1 << 18))) | (1 << 9) | (1 << 10);
        asm!("mov cr0, {}", in(reg) cr0, options(nostack));
        asm!("mov cr4, {}", in(reg) cr4, options(nostack));
        for msr in [0xc0000100u32, 0xc0000101, 0xc0000102] {
            asm!("wrmsr", in("ecx") msr, in("eax") 0u32, in("edx") 0u32, options(nostack));
        }
    }
    let original: u64;
    // SAFETY: ring-0 BSP root readback.
    unsafe {
        asm!("mov {}, cr3",out(reg) original,options(nomem,nostack,preserves_flags));
    }
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 0xff) as u8;
    let old = direct_address(offset, original & ADDRESS_MASK, bits).unwrap() as *const u64;
    // SAFETY: retained loader root is readable through the validated direct map.
    let slot = (1..256)
        .find(|&i| unsafe { old.add(i).read_volatile() == 0 })
        .expect("runtime user slot");
    let blob = ptr::addr_of!(ev_runtime_blob);
    let length = (ptr::addr_of!(ev_runtime_blob_end) as usize)
        .checked_sub(blob as usize)
        .unwrap();
    assert!(length > 0 && length < FRAME_SIZE as usize);
    let mut proof = Proof {
        faults: 0,
        survivors: 0,
        quanta: 0,
        messages: 0,
        blocks: 0,
        signals: 0,
        deadlines: 0,
        idle_ticks: 0,
        terminated: 0,
        reclaimed: 0,
        discarded: 0,
        freed_frames: 0,
        reused_frames: 0,
        shared_objects: 0,
        shared_maps: 0,
        denied_maps: 0,
        revoked_maps: 0,
        revoked_denials: 0,
        notifications: 0,
        anonymous_allocations: 0,
        anonymous_frees: 0,
    };
    let available_before = frames.remaining_frames();
    let reuse_before = frames.reused_frames();
    for mode in 0..3 {
        // SAFETY: distinct claimed roots preserve privileged controller mappings.
        let mut roots = unsafe {
            [
                UserRoot::new(offset, bits, original & ADDRESS_MASK, slot, frames),
                UserRoot::new(offset, bits, original & ADDRESS_MASK, slot, frames),
            ]
        };
        let base = roots[0].base();
        let mut aliases = [ptr::null_mut(); 2];
        // SAFETY: inactive private roots; freshly allocated code/data/stack pages
        // are zeroed and only the bounded, position-independent payload is copied.
        unsafe {
            for (i, root) in roots.iter_mut().enumerate() {
                let code = root.page(frames, FRAME_SIZE, UserPermission::ReadExecute);
                ptr::copy_nonoverlapping(blob, code.cast::<u8>(), length);
                aliases[i] = root.page(frames, 3 * FRAME_SIZE, UserPermission::ReadWrite);
                aliases[i].write_volatile(if i == 0 { 0x11111111 } else { 0x22222222 });
                root.page(frames, 5 * FRAME_SIZE, UserPermission::ReadWrite);
            }
        }
        let mut authority = Authority::new();
        let spaces = [
            authority.create_space().unwrap(),
            authority.create_space().unwrap(),
        ];
        let receive = authority
            .create_root(
                spaces[0],
                Kind::Endpoint,
                Rights::SEND
                    | Rights::RECEIVE
                    | Rights::CONTROL
                    | Rights::DERIVE
                    | Rights::TRANSFER,
            )
            .unwrap();
        let send = authority
            .derive(spaces[0], receive, spaces[1], Rights::SEND)
            .unwrap();
        let custodian = authority.create_space().unwrap();
        let fault_send = authority
            .create_root(
                custodian,
                Kind::Endpoint,
                Rights::RECEIVE
                    | Rights::CONTROL
                    | Rights::DERIVE
                    | Rights::SEND
                    | Rights::TRANSFER,
            )
            .unwrap();
        let fault_receive = authority
            .derive(
                custodian,
                fault_send,
                spaces[0],
                Rights::RECEIVE | Rights::CONTROL,
            )
            .unwrap();
        let mut fault_mailbox = Mailbox::new(&mut authority, spaces[0], fault_receive).unwrap();
        let mut notifications = 0;
        let mut fault_drops = 0;
        let mut fault_tickets = [None; 2];
        let backing = frames.allocate().expect("shared backing");
        let shared_alias = direct_address(offset, backing.start(), bits).unwrap() as *mut u64;
        // SAFETY: new owned backing, no mappings or user-visible grant yet.
        unsafe {
            for i in 0..512 {
                shared_alias.add(i).write_volatile(0);
            }
        }
        let (mut memory_object, memory_root) =
            MemoryObject::new(&mut authority, custodian, backing).unwrap();
        let memory = authority
            .derive(
                custodian,
                memory_root,
                spaces[1],
                Rights::READ
                    | Rights::WRITE
                    | Rights::MAP
                    | Rights::DERIVE
                    | Rights::TRANSFER
                    | Rights::REVOKE,
            )
            .unwrap();
        let lease = memory_object
            .map(&authority, spaces[1], memory, true)
            .unwrap();
        // SAFETY: retained initialized backing, inactive private root, IF=0.
        unsafe {
            roots[1].map_shared(lease, 7 * FRAME_SIZE).unwrap();
        }
        assert_eq!(
            memory_object
                .destroy(&mut authority, custodian, memory_root)
                .err(),
            Some(ev_kernel::memory_object::Error::Busy)
        );
        let mut shared_maps = 1;
        let mut denied_maps = 0;
        let mut revoked_maps = 0;
        let mut revoked_denials = 0;
        let mut revocations = 0;
        let grant = authority
            .derive(
                spaces[1],
                memory,
                spaces[1],
                Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::REVOKE,
            )
            .unwrap();
        let mut mailbox = Mailbox::new(&mut authority, spaces[0], receive).unwrap();
        // A second endpoint belongs to the process that will fault. Two
        // accepted messages exercise live-sender return and both-peer cleanup.
        let dead_receive = authority
            .create_root(
                spaces[1],
                Kind::Endpoint,
                Rights::RECEIVE
                    | Rights::CONTROL
                    | Rights::SEND
                    | Rights::DERIVE
                    | Rights::TRANSFER,
            )
            .unwrap();
        let dead_send = authority
            .derive(spaces[1], dead_receive, spaces[0], Rights::SEND)
            .unwrap();
        let mut orphan_mailbox = Mailbox::new(&mut authority, spaces[1], dead_receive).unwrap();
        let mut return_tickets = [Ticket(0); 2];
        for ticket in &mut return_tickets {
            let cap = authority
                .derive(
                    spaces[1],
                    memory,
                    spaces[0],
                    Rights::READ | Rights::TRANSFER,
                )
                .unwrap();
            *ticket = orphan_mailbox
                .send(
                    &mut authority,
                    spaces[0],
                    dead_send,
                    Outgoing {
                        bytes: b"retained",
                        capability: Some(cap),
                        deadline: Deadline::after(crate::timer::now(), 10000).unwrap(),
                    },
                    crate::timer::now(),
                )
                .unwrap();
        }
        let entries = [
            ptr::addr_of!(ev_runtime_good),
            ptr::addr_of!(ev_runtime_bad),
        ];
        let mut fx_contexts = [FxState::CLEAN; 2];
        let mut contexts = entries.map(|entry| {
            UserContext::new(
                base + FRAME_SIZE + (entry as u64 - blob as u64),
                base + 6 * FRAME_SIZE,
            )
            .unwrap()
        });
        for (i, frame) in contexts.iter_mut().enumerate() {
            frame.registers[8] = base + 3 * FRAME_SIZE;
            frame.registers[11] = if i == 0 { receive.0 } else { send.0 };
            frame.registers[7] = grant.0;
            frame.registers[6] = mode;
            frame.registers[5] = return_tickets[0].0;
            frame.registers[4] = fault_receive.0;
        }
        let mut scheduler = Scheduler::new();
        let root_job = scheduler
            .create_job_with_limits(Limits::new(10000, 16, 2, 2))
            .unwrap();
        let jobs = [
            scheduler
                .create_child_job(root_job, Limits::new(5000, 8, 1, 1))
                .unwrap(),
            scheduler
                .create_child_job(root_job, Limits::new(5000, 8, 1, 1))
                .unwrap(),
        ];
        let (allocator, allocation_cap) =
            AllocationDomain::bind(&mut authority, &scheduler, spaces[0], custodian, jobs[0])
                .unwrap();
        contexts[0].registers[13] = allocation_cap.0;
        let mut anonymous: [Option<Anonymous>; 2] = [None, None];
        // Seven private frames each; the shared backing stays attributed to its
        // originating sender Job until its final mapping/authority is retired.
        scheduler.charge_frames(jobs[0], 7).unwrap();
        scheduler.charge_frames(jobs[1], 8).unwrap();
        assert_eq!(
            scheduler.charge_frames(jobs[0], 2),
            Err(ev_kernel::scheduler::Error::Budget)
        );
        assert_eq!(scheduler.usage(root_job, Resource::Frames), Ok(15));
        let processes = jobs.map(|j| scheduler.create_process(j).unwrap());
        let threads = processes.map(|p| scheduler.create_thread(p).unwrap());
        let mut fault_records = [None; 2];
        let mut receive_waiters = WaitQueue::new();
        let mut pending: [Option<(Handle, Deadline)>; 2] = [None; 2];
        let mut blocks = 0;
        let mut signals = 0;
        let mut deadlines = 0;
        let mut idle_ticks = 0;
        let mut quanta = [0u64; 2];
        let mut calls = [0u64; 2];
        let mut success = false;
        let mut messages = 0;
        let mut reclaimed = 0;
        let mut discarded = 0;
        let mut terminated = 0;
        let deadline = Deadline::after(crate::timer::now(), 10000).unwrap();
        // SAFETY: initialized BSP IRQ0; controller remains IF=0 until user IRET.
        unsafe {
            crate::timer::start_runtime();
        }
        for _ in 0..1024 {
            for (i, root) in roots.iter_mut().enumerate() {
                if let Some(allocation) = &mut anonymous[i] {
                    // SAFETY: original root active, IF=0, AP parked. This object
                    // has its own lease and cannot invalidate another object's leaf.
                    unsafe {
                        root.discard_invalid_shared(&authority, &mut allocation.object);
                    }
                }
                // SAFETY: every trap returns to the retained controller root;
                // no other CPU uses these private mappings. Invalidate all
                // revoked/closed-domain leases before any user can resume.
                let invalidated =
                    unsafe { root.discard_invalid_shared(&authority, &mut memory_object) };
                if let Some((
                    address,
                    ev_kernel::memory_object::Error::Authority(
                        ev_kernel::capability::Error::Revoked,
                    ),
                )) = invalidated
                {
                    let entry = base
                        + FRAME_SIZE
                        + (ptr::addr_of!(ev_runtime_revoked_read) as u64 - blob as u64);
                    // SAFETY: independent finite read probe, no scheduled user
                    // entry active. Exact CPL3 nonpresent PF must occur at the
                    // revoked address. Probe does not write the user stack.
                    unsafe {
                        root.activate();
                        crate::traps::run_user(
                            entry,
                            address,
                            0,
                            ev_kernel::user::UserTrap {
                                vector: 14,
                                error: 4,
                                ip: entry,
                                address,
                                stack_top: base + 6 * FRAME_SIZE,
                            },
                        );
                        asm!("mov cr3, {}", in(reg) original, options(nostack,preserves_flags));
                    }
                    revoked_maps += 1;
                }
            }
            scheduler.advance(crate::timer::now()).unwrap();
            receive_waiters.reap(&scheduler);
            let Some(dispatch) = scheduler.dispatch(0).unwrap() else {
                if threads
                    .iter()
                    .any(|&t| matches!(scheduler.state(t), Ok(State::Blocked { .. })))
                {
                    idle_tick();
                    idle_ticks += 1;
                    continue;
                }
                break;
            };
            let index = threads.iter().position(|&t| t == dispatch.thread).unwrap();
            assert_eq!(dispatch.job, jobs[index]);
            if let Some((endpoint, deadline)) = pending[index].take() {
                contexts[index].registers[14] = match dispatch.wake {
                    Some(_) if deadline.reached(crate::timer::now()) => {
                        deadlines += 1;
                        4
                    }
                    Some(WakeReason::Deadline) => {
                        deadlines += 1;
                        4
                    }
                    Some(WakeReason::Signal) => match mailbox.receive(
                        &mut authority,
                        spaces[index],
                        endpoint,
                        crate::timer::now(),
                    ) {
                        Ok(delivery) => {
                            deliver(&mut contexts[index], delivery);
                            messages += 1;
                            0
                        }
                        Err(IpcError::Empty) => 2,
                        Err(_) => 1,
                    },
                    None => panic!("blocked receive resumed without a wake reason"),
                };
            }
            assert!(
                contexts[index].resumable(),
                "invalid context escaped return validation"
            );
            #[cfg(feature = "test-fx-corruption")]
            if index == 0 && quanta[index] > 0 {
                fx_contexts[index].0[160] ^= 1; // XMM0 low byte after preemption.
            }
            roots[index].activate();
            // SAFETY: retained selected root, private FX state and BSP exclusion;
            // the shared trap runner restores the controller CR3 before returning.
            let (mut frame, address) =
                unsafe { resume_context(&contexts[index], &mut fx_contexts[index], original) };
            let mut stopped = false;
            match frame.vector {
                32 => {
                    scheduler.charge_cpu(0, 1).expect("user CPU tick budget");
                    quanta[index] += 1;
                }
                128 => {
                    calls[index] += 1;
                    frame.registers[14] = match decode(&frame) {
                        Ok(Call::Yield) => 0,
                        Ok(Call::Exit(code)) => {
                            assert_ne!(code, 99, "user register/state fixture failed");
                            scheduler.exit(0).unwrap();
                            stopped = true;
                            if index == 0 && code == 0 && fault_records[1].is_some() {
                                success = true;
                            }
                            0
                        }
                        Ok(Call::Quanta) => quanta[index],
                        Ok(Call::Allocate(cap)) => {
                            if anonymous[index].is_some() {
                                2
                            } else {
                                match allocator.allocate(
                                    &mut authority,
                                    &mut scheduler,
                                    frames,
                                    spaces[index],
                                    cap,
                                ) {
                                    Err(ev_kernel::allocation::Error::Denied) => 1,
                                    Err(_) => 2,
                                    Ok(mut allocation) => {
                                        let lease = allocation
                                            .object
                                            .map(
                                                &authority,
                                                spaces[index],
                                                allocation.capability,
                                                true,
                                            )
                                            .unwrap();
                                        let alias = direct_address(offset, lease.physical(), bits)
                                            .unwrap()
                                            as *mut u64;
                                        // SAFETY: exclusively owned new backing; no user can run
                                        // before every byte is zero and mapping setup has succeeded.
                                        unsafe {
                                            for i in 0..512 {
                                                alias.add(i).write_volatile(0);
                                            }
                                            for i in 0..512 {
                                                assert_eq!(alias.add(i).read_volatile(), 0);
                                            }
                                        }
                                        // SAFETY: inactive private root, IF=0, exclusive initialized
                                        // backing and unique anonymous address separate from shared IPC.
                                        match unsafe {
                                            roots[index].map_shared(lease, 9 * FRAME_SIZE)
                                        } {
                                            Ok(()) => {
                                                frame.registers[9] = base + 9 * FRAME_SIZE;
                                                frame.registers[11] = allocation.capability.0;
                                                anonymous[index] = Some(allocation);
                                                proof.anonymous_allocations += 1;
                                                0
                                            }
                                            Err(lease) => {
                                                allocation.object.unmap(lease).unwrap();
                                                // SAFETY: no hardware mapping was installed.
                                                unsafe {
                                                    free_anonymous(
                                                        allocation,
                                                        &mut roots[index],
                                                        &mut authority,
                                                        spaces[index],
                                                        custodian,
                                                        frames,
                                                        offset,
                                                        bits,
                                                    );
                                                }
                                                scheduler.release_frames(jobs[index], 1).unwrap();
                                                2
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Call::Free(cap)) => {
                            if anonymous[index].as_ref().is_some_and(|allocation| {
                                allocation.capability == cap
                                    && authority
                                        .authorize(
                                            spaces[index],
                                            cap,
                                            Kind::Memory,
                                            Rights::CONTROL,
                                        )
                                        .is_ok()
                            }) {
                                let allocation = anonymous[index].take().unwrap();
                                // SAFETY: current thread returned to controller, all roots inactive.
                                unsafe {
                                    free_anonymous(
                                        allocation,
                                        &mut roots[index],
                                        &mut authority,
                                        spaces[index],
                                        custodian,
                                        frames,
                                        offset,
                                        bits,
                                    );
                                }
                                scheduler.release_frames(jobs[index], 1).unwrap();
                                let entry = base
                                    + FRAME_SIZE
                                    + (ptr::addr_of!(ev_runtime_revoked_read) as u64 - blob as u64);
                                // SAFETY: root inactive, finite exact CPL3 read probe; freed
                                // address must fault before any allocator reuse can expose it.
                                unsafe {
                                    roots[index].activate();
                                    crate::traps::run_user(
                                        entry,
                                        base + 9 * FRAME_SIZE,
                                        0,
                                        ev_kernel::user::UserTrap {
                                            vector: 14,
                                            error: 4,
                                            ip: entry,
                                            address: base + 9 * FRAME_SIZE,
                                            stack_top: base + 6 * FRAME_SIZE,
                                        },
                                    );
                                    asm!("mov cr3, {}", in(reg) original, options(nostack,preserves_flags));
                                }
                                proof.anonymous_frees += 1;
                                0
                            } else {
                                1
                            }
                        }
                        Ok(Call::Revoke(cap)) => {
                            if authority.revoke(spaces[index], cap).is_ok() {
                                revocations += 1;
                                0
                            } else {
                                1
                            }
                        }
                        Ok(Call::MapShared {
                            capability,
                            writable,
                        }) => {
                            match memory_object.map(&authority, spaces[index], capability, writable)
                            {
                                Ok(lease) => {
                                    // SAFETY: current serialized root, validated object backing,
                                    // one fixed shared slot and no concurrent AP mapping access.
                                    match unsafe { roots[index].map_shared(lease, 7 * FRAME_SIZE) }
                                    {
                                        Ok(()) => {
                                            shared_maps += 1;
                                            0
                                        }
                                        Err(lease) => {
                                            memory_object.unmap(lease).unwrap();
                                            1
                                        }
                                    }
                                }
                                Err(ev_kernel::memory_object::Error::Authority(
                                    ev_kernel::capability::Error::Revoked,
                                )) => {
                                    revoked_denials += 1;
                                    1
                                }
                                Err(_) => {
                                    denied_maps += 1;
                                    1
                                }
                            }
                        }
                        Ok(Call::Reclaim(ticket)) => match orphan_mailbox.reclaim(
                            &mut authority,
                            spaces[index],
                            Ticket(ticket),
                            crate::timer::now(),
                        ) {
                            Ok(Reclaimed::Capability(cap)) => {
                                frame.registers[11] = cap.0;
                                reclaimed += 1;
                                0
                            }
                            _ => 1,
                        },
                        Ok(Call::ReceiverWaiting) => u64::from(matches!(
                            scheduler.state(threads[0]),
                            Ok(State::Blocked { .. })
                        )),
                        Ok(Call::ReceiveFault(endpoint)) => match fault_mailbox.receive(
                            &mut authority,
                            spaces[index],
                            endpoint,
                            crate::timer::now(),
                        ) {
                            Ok(delivery) => {
                                let record =
                                    FaultRecord::decode(&delivery.bytes[..delivery.length])
                                        .expect("kernel fault record encoding");
                                frame.registers[9] = record.vector;
                                frame.registers[11] = record.error;
                                frame.registers[12] = record.address;
                                frame.registers[7] = record.instruction;
                                frame.registers[6] = record.process;
                                frame.registers[4] = record.thread;
                                notifications += 1;
                                0
                            }
                            Err(IpcError::Empty) => 2,
                            Err(_) => 1,
                        },
                        Ok(Call::Inspect { capability, rights }) => u64::from(
                            authority
                                .authorize(spaces[index], capability, Kind::Memory, rights)
                                .is_err(),
                        ),
                        Ok(Call::Send {
                            endpoint,
                            value,
                            capability,
                        }) => {
                            let sent = mailbox
                                .send(
                                    &mut authority,
                                    spaces[index],
                                    endpoint,
                                    Outgoing {
                                        bytes: &value.to_le_bytes(),
                                        capability,
                                        deadline,
                                    },
                                    crate::timer::now(),
                                )
                                .is_ok();
                            if sent && receive_waiters.wake_one(&mut scheduler) {
                                signals += 1;
                            }
                            u64::from(!sent)
                        }
                        Ok(Call::ReceiveWait { endpoint, ticks }) => {
                            match Deadline::after(crate::timer::now(), ticks) {
                                None => 3,
                                Some(deadline) => match mailbox.receive(
                                    &mut authority,
                                    spaces[index],
                                    endpoint,
                                    crate::timer::now(),
                                ) {
                                    Ok(delivery) => {
                                        deliver(&mut frame, delivery);
                                        messages += 1;
                                        0
                                    }
                                    Err(IpcError::Empty) => {
                                        // Predicate and enrollment share the IF=0 controller owner
                                        // with producers. No interrupt can consume/enqueue messages.
                                        if receive_waiters
                                            .block(&mut scheduler, 0, deadline)
                                            .is_ok()
                                        {
                                            pending[index] = Some((endpoint, deadline));
                                            stopped = true;
                                            blocks += 1;
                                            2 // replaced on signal/deadline before user resumption
                                        } else {
                                            2
                                        }
                                    }
                                    Err(_) => 1,
                                },
                            }
                        }
                        Ok(Call::Receive(endpoint)) => match mailbox.receive(
                            &mut authority,
                            spaces[index],
                            endpoint,
                            crate::timer::now(),
                        ) {
                            Ok(delivery) => {
                                deliver(&mut frame, delivery);
                                messages += 1;
                                0
                            }
                            Err(IpcError::Empty) => 2,
                            Err(_) => 1,
                        },
                        _ => 3,
                    };
                }
                _ if frame.ordinary_user_fault() => {
                    fault_records[index] = Some(Fault {
                        vector: frame.vector,
                        error: frame.error,
                        address,
                    });
                    scheduler.exit(0).unwrap();
                    stopped = true;
                }
                _ => panic!("unexpected user runtime event"),
            }
            if !stopped && !frame.resumable() {
                // A user-controlled invalid return frame takes the same complete
                // retirement path. Vector 13 denotes this synthetic return fault.
                fault_records[index] = Some(Fault {
                    vector: 13,
                    error: 0,
                    address: 0,
                });
                scheduler.exit(0).unwrap();
                stopped = true;
            }
            contexts[index] = frame;
            if scheduler.state(threads[index]) == Ok(State::Exited) {
                // SAFETY: controller regained execution, user/handler inactive,
                // IF=0 and AP parked. Remove the process root before retirement.
                unsafe {
                    asm!("mov cr3, {}", in(reg) original, options(nostack,preserves_flags));
                }
                scheduler.terminate_process(processes[index]).unwrap();
                if let Some(fault) = fault_records[index] {
                    let record = FaultRecord {
                        process: processes[index].diagnostic_id(),
                        thread: threads[index].diagnostic_id(),
                        vector: fault.vector,
                        error: fault.error,
                        address: fault.address,
                        instruction: frame.rip,
                    };
                    // Nonblocking diagnostics: a missing/full/dead observer never
                    // prevents containment. Only this kernel-held SEND can publish.
                    match fault_mailbox.send(
                        &mut authority,
                        custodian,
                        fault_send,
                        Outgoing {
                            bytes: &record.encode(),
                            capability: None,
                            deadline: Deadline::after(crate::timer::now(), 10000).unwrap(),
                        },
                        crate::timer::now(),
                    ) {
                        Ok(ticket) => fault_tickets[index] = Some(ticket),
                        Err(_) => fault_drops += 1,
                    }
                }
                assert!(scheduler.create_thread(processes[index]).is_err());
                if let Some(allocation) = anonymous[index].take() {
                    // SAFETY: terminated process, inactive root, IF=0 and AP parked.
                    unsafe {
                        free_anonymous(
                            allocation,
                            &mut roots[index],
                            &mut authority,
                            spaces[index],
                            custodian,
                            frames,
                            offset,
                            bits,
                        );
                    }
                    scheduler.release_frames(jobs[index], 1).unwrap();
                    proof.anonymous_frees += 1;
                }
                authority.close_space(spaces[index]).unwrap();
                assert!(!authority.is_live_space(spaces[index]));
                if index == 0 {
                    mailbox.receiver_died(spaces[index]).unwrap();
                    fault_mailbox.receiver_died(spaces[index]).unwrap();
                    for ticket in fault_tickets.iter_mut().filter_map(Option::take) {
                        assert!(matches!(
                            fault_mailbox.reclaim(
                                &mut authority,
                                custodian,
                                ticket,
                                crate::timer::now()
                            ),
                            Ok(Reclaimed::NoCapability) | Err(IpcError::InvalidTicket)
                        ));
                    }
                } else {
                    orphan_mailbox.receiver_died(spaces[index]).unwrap();
                }
                receive_waiters.reap(&scheduler);
                pending[index] = None;
                discarded += mailbox
                    .reap_dead_senders(&mut authority, crate::timer::now())
                    .unwrap();
                discarded += orphan_mailbox
                    .reap_dead_senders(&mut authority, crate::timer::now())
                    .unwrap();
                terminated += 1;
            }
            if !stopped {
                scheduler.yield_cpu(0).unwrap();
            }
        }
        // SAFETY: no user/handler active, controller IF=0 and exclusive PIC owner.
        unsafe {
            crate::timer::stop_runtime();
            asm!("mov cr3, {}",in(reg) original,options(nostack,preserves_flags));
        }
        assert!(success, "healthy user process did not survive peer fault");
        assert_eq!(messages, 1);
        assert_eq!(notifications, 1);
        assert_eq!(fault_drops, 0);
        proof.notifications += notifications;
        assert_eq!(terminated, 2);
        assert_eq!(reclaimed, 1);
        assert_eq!(discarded, 1);
        mailbox.retire_empty(&mut authority).unwrap();
        fault_mailbox.retire_empty(&mut authority).unwrap();
        orphan_mailbox.retire_empty(&mut authority).unwrap();
        assert_eq!(blocks, 2);
        assert_eq!(signals, 1);
        assert_eq!(deadlines, 1);
        assert!(idle_ticks >= 1);
        assert!(receive_waiters.is_empty(&scheduler));
        assert!(pending.iter().all(Option::is_none));
        assert!(fault_records[0].is_none());
        let fault = fault_records[1].expect("faulting user process");
        assert_eq!(fault.vector, [6, 14, 13][mode as usize]);
        if mode == 1 {
            assert_eq!(fault.address, 0);
            assert_ne!(fault.error & 4, 0);
        } else {
            assert_eq!(fault.error, 0);
        }
        for (i, thread) in threads.into_iter().enumerate() {
            assert_eq!(scheduler.state(thread), Ok(State::Exited));
            assert!(quanta[i] >= 2);
            assert!(calls[i] >= 5);
        }
        // SAFETY: retained private RAM aliases, user work stopped, no references.
        unsafe {
            for (i, p) in aliases.into_iter().enumerate() {
                assert_eq!(
                    p.read_volatile(),
                    if i == 0 { 0x11111111 } else { 0x22222222 }
                );
                assert!(p.add(1).read_volatile() > 0);
            }
        }
        assert_eq!(revocations, 1);
        assert_eq!(revoked_maps, 1);
        assert_eq!(revoked_denials, 1);
        proof.revoked_maps += revoked_maps;
        proof.revoked_denials += revoked_denials;
        assert_eq!(shared_maps, 2);
        assert_eq!(denied_maps, 2);
        // SAFETY: private user contexts retired and original root restored.
        // Both leases are removed before any backing frame can be reclaimed.
        unsafe {
            assert_eq!(shared_alias.read_volatile(), 0xdecafbad);
            for root in &mut roots {
                root.unmap_shared(&mut memory_object);
            }
        }
        let shared_frame = memory_object
            .destroy(&mut authority, custodian, memory_root)
            .unwrap_or_else(|_| panic!("shared backing still mapped"));
        assert!(
            authority
                .authorize(custodian, memory_root, Kind::Memory, Rights::READ)
                .is_err()
        );
        // SAFETY: all shared mappings quiescent, exclusive returned frame. No
        // alias is used after the final scrub and allocator handoff below.
        unsafe {
            for i in 0..512 {
                shared_alias.add(i).write_volatile(0);
            }
            for i in 0..512 {
                assert_eq!(shared_alias.add(i).read_volatile(), 0);
            }
        }
        frames.reclaim(shared_frame).unwrap();
        authority.close_space(custodian).unwrap();
        proof.shared_objects += 1;
        proof.shared_maps += shared_maps;
        proof.denied_maps += denied_maps;
        for root in roots {
            #[cfg(feature = "test-reclaim-active-root")]
            root.activate();
            // SAFETY: all process threads retired, controller restored original
            // CR3, AP parked and never used these private roots. Alias checks
            // above are finished; no former data/table pointer is used again.
            // Negative image intentionally violates the root condition so the
            // readback guard must reject it before touching any page.
            proof.freed_frames += unsafe { root.retire(frames) } as u64;
        }
        scheduler.release_frames(jobs[0], 7).unwrap();
        scheduler.release_frames(jobs[1], 8).unwrap();
        for (i, job) in jobs.into_iter().enumerate() {
            assert_eq!(scheduler.usage(job, Resource::CpuTicks), Ok(quanta[i]));
        }
        assert_eq!(
            scheduler.usage(root_job, Resource::CpuTicks),
            Ok(quanta.iter().sum())
        );
        for job in [root_job, jobs[0], jobs[1]] {
            for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
                assert_eq!(scheduler.usage(job, resource), Ok(0));
            }
        }
        assert_eq!(frames.remaining_frames(), available_before);
        proof.faults += 1;
        proof.survivors += 1;
        proof.quanta += quanta.iter().sum::<u64>();
        proof.messages += messages;
        proof.blocks += blocks;
        proof.signals += signals;
        proof.deadlines += deadlines;
        proof.idle_ticks += idle_ticks;
        proof.terminated += terminated;
        proof.reclaimed += reclaimed;
        proof.discarded += discarded as u64;
    }
    let restored: u64;
    // SAFETY: ring-0 readback of the restored retained root.
    unsafe {
        asm!("mov {}, cr3",out(reg) restored,options(nomem,nostack,preserves_flags));
    }
    assert_eq!(restored, original);
    proof.reused_frames = frames.reused_frames() - reuse_before;
    assert_eq!(proof.freed_frames, 42);
    assert!((28..=42).contains(&proof.reused_frames));
    proof
}

/// # Safety
/// Inactive root, IF=0, no other CPU/alias uses this single-page allocation.
#[allow(clippy::too_many_arguments)]
unsafe fn free_anonymous(
    mut allocation: Anonymous,
    root: &mut UserRoot,
    authority: &mut Authority,
    owner: ev_kernel::capability::SpaceId,
    custodian: ev_kernel::capability::SpaceId,
    frames: &mut BootstrapFrames,
    offset: u64,
    bits: u8,
) {
    // SAFETY: caller proves quiescence and matching object ownership.
    unsafe {
        root.unmap_shared(&mut allocation.object);
    }
    let frame = allocation
        .object
        .destroy(authority, custodian, allocation.custody)
        .unwrap();
    authority.close(owner, allocation.capability).unwrap();
    authority.close(custodian, allocation.custody).unwrap();
    let alias = direct_address(offset, frame.start(), bits).unwrap() as *mut u64;
    // SAFETY: exclusive, unmapped backing before returning its allocator claim.
    unsafe {
        for i in 0..512 {
            alias.add(i).write_volatile(0);
        }
        for i in 0..512 {
            assert_eq!(alias.add(i).read_volatile(), 0);
        }
    }
    frames
        .reclaim(frame)
        .expect("anonymous recycle capacity/provenance");
}
