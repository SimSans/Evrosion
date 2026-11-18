use super::*;
use core::{mem::MaybeUninit, ptr};
static mut WORLD: MaybeUninit<World> = MaybeUninit::uninit();
/// # Safety
/// Sole BSP/IF0 controller after owned traps/timer/FX setup, APs parked, PCID
/// off, immutable boot assets/direct map/GOP and exclusive allocator retained.
#[inline(never)] // Initialization temporaries end before runtime loading/dispatch.
unsafe fn prepare(
    offset: u64,
    frames: &mut BootstrapFrames,
    fb: ev_boot_contract::Framebuffer,
    assets: &Assets,
    max_ticks: u64,
    log: &mut dyn Write,
) -> &'static mut World {
    assert!(!matches!(max_ticks, 0 | u64::MAX));
    let original: u64;
    // SAFETY: privileged read only in the sole boot controller at IF0.
    unsafe {
        asm!("mov {}, cr3",out(reg)original,options(nomem,nostack,preserves_flags));
    }
    let hw = Hardware {
        offset,
        bits: (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8,
        original: original & ev_kernel::mapping::ADDRESS_MASK,
    };
    // SAFETY: same verified hardware boundary and once-claimed resident stores.
    let mut core = unsafe { resident::initialize(hw, frames, fb, assets) };
    let process = core.s.create_held_process(core.root_job).unwrap();
    let thread = core.s.create_thread(process).unwrap();
    let (_, target) = core
        .domains
        .take()
        .unwrap()
        .into_target(process, core.root_job);
    let mut custodian =
        Custodian::new_root_v5(EPOCH, core.manifest, core.backing.custody, core.catalog);
    let attempt = custodian.begin(crate::timer::now()).unwrap();
    let (mut binding, token) = custodian.prepare(attempt, core.a, core.s, target).unwrap();
    let mut grants = [Handle(0); 37];
    grants.copy_from_slice(binding.grants(token).unwrap());
    let startup = binding.bootstrap_record_v5(token).unwrap();
    let record = ev_kernel::startup_record::Record::root_v5(&startup).unwrap();
    let plan = binding.executable(token).unwrap();
    core.s
        .charge_frames(core.root_job, plan.required_frames())
        .unwrap();
    let meta = Metadata {
        process,
        thread,
        job: core.root_job,
        domain: target.destination,
        frames: plan.required_frames(),
    };
    // SAFETY: actual held Root plan/typed record; resident slot0 is unclaimed.
    let owner = unsafe {
        resident::place_image(
            0,
            PhysicalImage::load(hw, None, &plan, record, frames).expect("actual V5 Root load"),
        )
    };
    for spec in mapping::ROOT {
        let extent = core.backing.extents[spec.role.selector() as usize - 1]
            .as_mut()
            .unwrap();
        // SAFETY: closed Root window and installed grant to its actual retained
        // initialized extent; no Root instruction has been admitted yet.
        unsafe {
            owner.install(
                core.a,
                extent,
                meta.domain,
                grants[spec.role.selector() as usize - 1],
                spec,
            )
        }
        .expect("actual Root external mapping");
    }
    owner
        .check(core.a, &core.backing.extents)
        .expect("actual V5 Root shared readback");
    let mut context = UserContext::new(plan.entry(), plan.stack_top()).unwrap();
    context.registers[8] = plan.bootstrap_page().unwrap();
    context.registers[9] = startup.len() as u64;
    let active = binding
        .activate_root_v5(
            core.a,
            core.s,
            token,
            thread,
            ImageLease::new(owner, meta, None),
            frames,
            &core.backing.extents,
        )
        .unwrap_or_else(|r| panic!("actual V5 Root admission:{:?}", r.error));
    custodian.confirm_active(&active).unwrap();
    core.rpc
        .register_thread(core.a, core.s, thread, meta.job, meta.domain, Some(token))
        .unwrap();
    let event_cap = grants[Role::RootEvents.selector() as usize - 1];
    let mailbox = Mailbox::new(core.a, meta.domain, event_cap).unwrap();
    let object = core
        .a
        .authorize(meta.domain, event_cap, Kind::Endpoint, RECEIVE)
        .unwrap()
        .identity();
    let now = crate::timer::now();
    let stop = Deadline::after(now, max_ticks).expect("finite V5 runtime cut");
    // SAFETY: exclusive once-claimed static residency. Initialize each finite
    // field independently; no World/actor/image-array stack temporary exists.
    let world = unsafe {
        let p = ptr::addr_of_mut!(WORLD).cast::<World>();
        ptr::addr_of_mut!((*p).core).write(core);
        ptr::addr_of_mut!((*p).hw).write(hw);
        ptr::addr_of_mut!((*p).root).write(Root {
            active: Some(active),
            meta,
            context,
            fx: FxState::CLEAN,
        });
        ptr::addr_of_mut!((*p).token).write(token);
        ptr::addr_of_mut!((*p).custodian).write(custodian);
        ptr::addr_of_mut!((*p).root_grants).write(grants);
        for i in 0..12 {
            ptr::addr_of_mut!((*p).actors)
                .cast::<Option<Actor>>()
                .add(i)
                .write(None);
            ptr::addr_of_mut!((*p).vacant)
                .cast::<Option<&'static mut PhysicalImage>>()
                .add(i)
                .write(None);
        }
        ptr::addr_of_mut!((*p).dynamic)
            .write(dynamic::State::claim().expect("V5 dynamic once-only owner"));
        ptr::addr_of_mut!((*p).spare_claimed).write(false);
        for i in 0..24 {
            ptr::addr_of_mut!((*p).wires)
                .cast::<Option<Wire>>()
                .add(i)
                .write(None);
        }
        ptr::addr_of_mut!((*p).pending).write([None; 8]);
        for i in 0..4 {
            ptr::addr_of_mut!((*p).selected)
                .cast::<grant::Selected>()
                .add(i)
                .write(grant::Selected::new());
        }
        ptr::addr_of_mut!((*p).images).write(assets.images);
        ptr::addr_of_mut!((*p).jobs).write([None; 16]);
        ptr::addr_of_mut!((*p).stop).write(stop);
        ptr::addr_of_mut!((*p).started).write(now);
        ptr::addr_of_mut!((*p).facts).write(Facts::default());
        ptr::addr_of_mut!((*p).root_exited).write(false);
        ptr::addr_of_mut!((*p).power).write(ev_kernel::session_power::Latch::new());
        ptr::addr_of_mut!((*p).log_retention).write(crate::session_log::Retention::new());
        &mut *p
    };
    world.wires[graph::ROOT_EVENTS_WIRE] =
        Some(Wire::new(object, meta.domain, mailbox, DeliveryMode::Async));
    world.event(log, "admitted", 0);
    let (spaces, handles, nodes, objects) = world.core.a.metadata_usage();
    let _ = writeln!(
        log,
        "EVROSION_M8_KERNEL_V5 phase=prepared sources=37 spaces={spaces} handles={handles} nodes={nodes} objects={objects} remaining_frames={} world_resident={} owner_slot={} tick={} deadline={} pit_divisor=1193 claimed_30min=false",
        frames.remaining_frames(),
        core::mem::size_of::<World>(),
        core::mem::size_of::<PhysicalImage>(),
        now,
        stop.tick()
    );
    world
}
/// # Safety
/// Same exclusive BSP/allocator/assets ownership as prepare; the returned
/// resident graph remains pinned across its actual user execution.
#[inline(never)]
pub(crate) unsafe fn run(
    offset: u64,
    frames: &mut BootstrapFrames,
    fb: ev_boot_contract::Framebuffer,
    assets: &Assets,
    max_ticks: u64,
    log: &mut dyn Write,
) -> Proof {
    // SAFETY: sole selected controller; initialization stack is fully returned
    // before the executor can load a child or enter a captured user context.
    let world = unsafe { prepare(offset, frames, fb, assets, max_ticks, log) };
    // SAFETY: exact pinned admitted graph/FX, controller root and allocator.
    unsafe { world.execute(frames, log) };
    Proof {
        starts: world.facts.starts,
        calls: world.facts.calls,
        replies: world.facts.replies,
        root_exited: world.root_exited,
        retained: true,
        checked_shutdown: world.power.completed_intent()
            == Some(ev_kernel::session_power::Intent::Shutdown),
        checked_restart: world.power.completed_intent()
            == Some(ev_kernel::session_power::Intent::Restart),
    }
}
