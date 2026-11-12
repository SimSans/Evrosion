//! A bounded physical executable owner behind ordinary capability mechanisms.
//! No generation selection, catalogue resolution or health decision belongs here.
use super::{Hardware, LoadedImage, ProcessImage};
use core::num::NonZeroU64;
use ev_kernel::{
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    fault::Record,
    mapping::ADDRESS_MASK,
    memory::BootstrapFrames,
    rpc::Rpc,
    scheduler::{Scheduler, State},
    service::{Metadata, Registry, Running},
    user_context::{FxState, UserContext},
};

#[derive(Default)]
pub(super) struct Facts {
    pub starts: u64,
    pub stops: u64,
    pub reaps: u64,
    pub identities: u64,
    pub fault_queries: u64,
    pub fault: Option<Record>,
    pub last: Option<Metadata>,
    pub image: Option<usize>,
    pub first_live_observe: Option<u64>,
    pub last_live_observe: Option<u64>,
    pub stop_tick: Option<u64>,
    pub stopped_live: bool,
}
pub(super) struct Lifecycle<'a> {
    vacant: Option<&'a mut LoadedImage>,
    running: Option<Running<ProcessImage<'a>>>,
    returned: Option<ProcessImage<'a>>,
    meta: Option<Metadata>,
    object: Option<usize>,
    admitted: bool,
    reaped: bool,
    registered: bool,
    fault: Option<Record>,
    pub context: UserContext,
    pub fx: FxState,
    pub facts: Facts,
}
impl<'a> Lifecycle<'a> {
    pub fn new(slot: &'a mut LoadedImage) -> Self {
        Self {
            vacant: Some(slot),
            running: None,
            returned: None,
            meta: None,
            object: None,
            admitted: false,
            reaped: false,
            registered: false,
            fault: None,
            context: UserContext::ZERO,
            fx: FxState::CLEAN,
            facts: Facts::default(),
        }
    }
    pub fn metadata(&self) -> Option<Metadata> {
        self.meta
    }
    pub fn image(&self) -> Option<&Running<ProcessImage<'a>>> {
        self.running.as_ref()
    }
    fn authorized(
        &self,
        r: &Registry<'_>,
        a: &Authority,
        caller: SpaceId,
        cap: Handle,
    ) -> Result<Metadata, u64> {
        let meta = r.metadata(a, caller, cap).map_err(|_| 1u64)?;
        if self.meta != Some(meta)
            || self.object
                != Some(
                    a.authorize(caller, cap, Kind::Process, Rights::CONTROL)
                        .map_err(|_| 1u64)?
                        .identity(),
                )
        {
            return Err(1);
        }
        Ok(meta)
    }
    pub fn create(
        &mut self,
        r: &mut Registry<'_>,
        a: &mut Authority,
        s: &mut Scheduler,
        caller: SpaceId,
        job: Handle,
        image: Handle,
    ) -> Result<Handle, u64> {
        if self.meta.is_some() || self.vacant.is_none() {
            return Err(2);
        }
        let cap = r
            .create_process(a, s, caller, job, image)
            .map_err(|_| 1u64)?;
        self.meta = Some(r.metadata(a, caller, cap).unwrap());
        self.facts.image = Some(
            a.authorize(caller, image, Kind::Memory, Rights::READ)
                .unwrap()
                .identity(),
        );
        self.object = Some(
            a.authorize(caller, cap, Kind::Process, Rights::CONTROL)
                .unwrap()
                .identity(),
        );
        self.admitted = false;
        self.reaped = false;
        self.registered = false;
        self.fault = None;
        Ok(cap)
    }
    /// # Safety
    /// Serialized inactive physical allocator/controller owner, IF0/AP parked.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn start(
        &mut self,
        r: &mut Registry<'static>,
        a: &Authority,
        s: &mut Scheduler,
        rpc: &mut Rpc,
        caller: SpaceId,
        cap: Handle,
        epoch: NonZeroU64,
        hw: &Hardware,
        frames: &mut BootstrapFrames,
    ) -> Result<(), u64> {
        let meta = self.authorized(r, a, caller, cap)?;
        if self.admitted || self.reaped || self.returned.is_some() {
            return Err(1);
        }
        let plan = r.plan(a, caller, cap).map_err(|_| 1u64)?;
        let record = r.startup(a, caller, cap, epoch).map_err(|_| 1u64)?;
        let slot = self.vacant.take().ok_or(2u64)?;
        // SAFETY: measured held target and unique inactive image slot. Loading
        // failure preflights before allocation; retain the slot on every refusal.
        match unsafe {
            LoadedImage::load_startup(
                hw.offset,
                hw.bits,
                hw.original & ADDRESS_MASK,
                &plan,
                Some(&record),
                frames,
            )
        } {
            Ok(loaded) => *slot = loaded,
            Err(_) => {
                self.vacant = Some(slot);
                return Err(2);
            }
        }
        let owner = ProcessImage {
            loaded: slot,
            process: meta.process,
            frames: meta.frames,
        };
        match r.start(a, s, caller, cap, epoch, owner) {
            Ok(running) => {
                self.context = running.initial_context().unwrap();
                self.fx = FxState::CLEAN;
                rpc.register_thread(a, s, meta.thread, meta.job, meta.domain, None)
                    .unwrap();
                self.running = Some(running);
                self.admitted = true;
                self.registered = true;
                self.facts.starts += 1;
                self.facts.last = Some(meta);
                Ok(())
            }
            Err(rejected) => {
                self.returned = Some(rejected.image);
                Err(1)
            }
        }
    }
    pub fn identity(
        &mut self,
        r: &Registry<'_>,
        a: &Authority,
        caller: SpaceId,
        cap: Handle,
    ) -> Result<(u64, u64), u64> {
        let meta = self.authorized(r, a, caller, cap)?;
        // A held plan is not actual admission. A faulted but unreaped admitted
        // process retains its exact identity for diagnostics and durable reports.
        if !self.admitted || self.reaped {
            return Err(1);
        }
        self.facts.identities += 1;
        Ok((meta.process.diagnostic_id(), meta.thread.diagnostic_id()))
    }
    pub fn field(
        &mut self,
        r: &Registry<'_>,
        a: &Authority,
        caller: SpaceId,
        cap: Handle,
        field: u64,
    ) -> Result<u64, u64> {
        let meta = self.authorized(r, a, caller, cap)?;
        if self.reaped {
            return Err(1);
        }
        let record = self.fault.ok_or(2u64)?;
        assert_eq!(
            (record.process, record.thread),
            (meta.process.diagnostic_id(), meta.thread.diagnostic_id())
        );
        let value = match field {
            1 => record.process,
            2 => record.thread,
            3 => record.vector,
            4 => record.error,
            5 => record.address,
            6 => record.instruction,
            _ => return Err(3),
        };
        self.facts.fault_queries += 1;
        Ok(value)
    }
    pub fn observe(
        &mut self,
        r: &Registry<'_>,
        a: &Authority,
        s: &Scheduler,
        caller: SpaceId,
        cap: Handle,
        now: u64,
    ) -> Result<bool, u64> {
        self.authorized(r, a, caller, cap)?;
        let done = r.observe(a, s, caller, cap).map_err(|_| 1u64)?;
        if self.admitted && !self.reaped && !done {
            self.facts.first_live_observe.get_or_insert(now);
            self.facts.last_live_observe = Some(now);
        }
        Ok(done)
    }
    #[allow(clippy::too_many_arguments)] // Same explicit serialized table owners as start/reap.
    pub fn stop(
        &mut self,
        r: &Registry<'_>,
        a: &mut Authority,
        s: &mut Scheduler,
        rpc: &mut Rpc,
        caller: SpaceId,
        cap: Handle,
        now: u64,
    ) -> Result<(), u64> {
        self.authorized(r, a, caller, cap)?;
        self.stop_owned(a, s, rpc, now)
    }
    pub fn stop_owned(
        &mut self,
        a: &mut Authority,
        s: &mut Scheduler,
        rpc: &mut Rpc,
        now: u64,
    ) -> Result<(), u64> {
        let meta = self.meta.ok_or(1u64)?;
        if self.reaped {
            return Ok(());
        }
        if matches!(s.state(meta.thread), Ok(State::Running(_))) {
            return Err(2);
        }
        if self.running.is_some() {
            self.facts.stop_tick = Some(now);
            self.facts.stopped_live = s
                .state(meta.thread)
                .is_ok_and(|state| state != State::Exited);
        }
        if let Some(running) = &mut self.running {
            running.stop(a, s).map_err(|_| 1u64)?;
        }
        // A never-admitted held target has no Running owner to inhibit; under
        // this same serialized scheduler owner, termination below prevents its
        // first dispatch. No private scheduler admission operation is exposed.
        s.terminate_process(meta.process).map_err(|_| 1u64)?;
        if self.registered {
            assert!(rpc.peer_died(s, meta.thread, now).unwrap().is_empty());
            self.registered = false;
        }
        if let Some(running) = self.running.take() {
            self.returned = Some(
                running
                    .finish(s)
                    .unwrap_or_else(|_| panic!("critical owner still live")),
            );
            self.facts.stops += 1;
        }
        Ok(())
    }
    pub fn fault(
        &mut self,
        a: &mut Authority,
        s: &mut Scheduler,
        rpc: &mut Rpc,
        frame: &UserContext,
        address: u64,
        now: u64,
    ) {
        let meta = self.meta.expect("actual dispatched critical identity");
        assert!(self.admitted && frame.ordinary_user_fault());
        let record = Record {
            process: meta.process.diagnostic_id(),
            thread: meta.thread.diagnostic_id(),
            vector: frame.vector,
            error: frame.error,
            address,
            instruction: frame.rip,
        };
        assert_eq!(Record::decode(&record.encode()), Some(record));
        self.fault = Some(record);
        self.facts.fault = Some(record);
        assert_eq!(s.exit(0), Ok(meta.thread));
        self.stop_owned(a, s, rpc, now).unwrap();
    }
    /// # Safety
    /// Actual stop restored controller CR3/IF0, APs parked, no external device,
    /// mapping or accepted RPC references to this critical root remain.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn reap(
        &mut self,
        r: &mut Registry<'_>,
        a: &mut Authority,
        s: &mut Scheduler,
        rpc: &mut Rpc,
        caller: SpaceId,
        cap: Handle,
        frames: &mut BootstrapFrames,
    ) -> Result<(), u64> {
        self.authorized(r, a, caller, cap)?;
        if self.reaped || !r.observe(a, s, caller, cap).map_err(|_| 1u64)? {
            return Err(1);
        }
        // SAFETY: exact authorized stopped target and identical retained
        // physical/reference ownership required by this method's contract.
        unsafe { self.reap_owned(r, a, s, rpc, frames) }
    }
    /// # Safety
    /// Same stopped physical ownership contract as reap(), using retained actual
    /// metadata after the public control handle was closed or revoked.
    pub unsafe fn reap_owned(
        &mut self,
        r: &mut Registry<'_>,
        a: &mut Authority,
        s: &mut Scheduler,
        rpc: &mut Rpc,
        frames: &mut BootstrapFrames,
    ) -> Result<(), u64> {
        let meta = self.meta.ok_or(1u64)?;
        if self.reaped {
            return Ok(());
        }
        if self.running.is_some() || self.registered || s.state(meta.thread) != Ok(State::Exited) {
            return Err(1);
        }
        if let Some(owner) = self.returned.take() {
            let loaded = owner.loaded;
            // SAFETY: non-device critical image stopped, no shared mappings,
            // registered RPC consumer or CPU can access its retained root.
            let count = unsafe { loaded.root.retire_in_place(frames) };
            assert_eq!(count as u64, meta.frames);
            self.vacant = Some(loaded);
        }
        s.release_frames(meta.job, meta.frames).unwrap();
        r.retire_stopped(a, s, meta.process).unwrap();
        if self.admitted {
            rpc.forget_thread(s, meta.thread).unwrap();
        }
        self.reaped = true;
        self.facts.reaps += 1;
        Ok(())
    }
    pub fn collect_closed(
        &mut self,
        r: &mut Registry<'_>,
        a: &mut Authority,
        s: &mut Scheduler,
    ) -> Result<bool, u64> {
        let Some(meta) = self.meta else {
            return Ok(false);
        };
        if !self.reaped {
            return Ok(false);
        }
        // Escaped live controls pin the row; never pretend they were closed or
        // reclaim the scheduler identity if metadata forgetting did not commit.
        if r.forget_retired(a, s, meta.process).is_err() {
            return Ok(false);
        }
        s.reclaim_process(meta.process).unwrap();
        self.meta = None;
        self.object = None;
        self.admitted = false;
        self.reaped = false;
        self.fault = None;
        self.context = UserContext::ZERO;
        self.fx = FxState::CLEAN;
        Ok(true)
    }
}
