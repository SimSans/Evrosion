//! Source state joins qualified initialization to actual actor events. Values
//! grant no authority; CPU exit never proves NIC stop or clears hardware debt.
#![forbid(unsafe_code)]
pub mod client;
pub mod download;
pub mod transfer;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    Driver,
    Service,
}
impl Node {
    pub const fn index(self) -> usize {
        self as usize
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub control: u64,
    pub process: u64,
    pub thread: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Unstarted,
    PreparingDriver,
    WaitingService,
    WaitingEntropy,
    Initializing,
    Running,
    ShuttingDown,
    HardwareStopped,
    Stopped,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    State,
    Identity,
    Clock,
    Expired,
    Event,
}
pub struct State {
    phase: Phase,
    actors: [Option<Identity>; 2],
    reported: [bool; 2],
    cut: u64,
    last: u64,
    prepared: bool,
    waiting: bool,
    initialized: bool,
}
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
impl State {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Unstarted,
            actors: [None; 2],
            reported: [false; 2],
            cut: 0,
            last: 0,
            prepared: false,
            waiting: false,
            initialized: false,
        }
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn prepared(&self) -> bool {
        self.prepared
    }
    pub fn waiting(&self) -> bool {
        self.waiting
    }
    pub fn unavailable(&self) -> bool {
        self.phase == Phase::Unavailable
    }
    fn observe(&mut self, now: u64) -> Result<(), Error> {
        if now == u64::MAX || now < self.last {
            self.phase = Phase::Unavailable;
            return Err(Error::Clock);
        }
        self.last = now;
        Ok(())
    }
    pub fn begin(&mut self, now: u64, cut: u64) -> Result<(), Error> {
        self.observe(now)?;
        if self.phase != Phase::Unstarted {
            return Err(Error::State);
        }
        if cut == u64::MAX
            || cut <= now
            || cut - now > ev_userspace_contract::root_v4::COLD_PREPARE_MAX_TICKS
        {
            return Err(Error::Clock);
        }
        self.cut = cut;
        self.phase = Phase::PreparingDriver;
        Ok(())
    }
    pub fn bind(&mut self, node: Node, actor: Identity) -> Result<(), Error> {
        if [actor.control, actor.process, actor.thread].contains(&0)
            || self.actors[node.index()].is_some()
            || self.actors.iter().flatten().any(|a| {
                a.control == actor.control || a.process == actor.process || a.thread == actor.thread
            })
        {
            return Err(Error::Identity);
        }
        if self.phase == Phase::Unstarted || self.phase == Phase::Unavailable {
            return Err(Error::State);
        }
        self.actors[node.index()] = Some(actor);
        Ok(())
    }
    pub fn event(
        &mut self,
        node: Node,
        actor: Identity,
        bytes: [u8; 8],
        now: u64,
    ) -> Result<(), Error> {
        self.observe(now)?;
        if self.actors[node.index()] != Some(actor) {
            return Err(Error::Identity);
        }
        self.expire(now)?;
        match (node, bytes) {
            (Node::Driver, b) if b == *b"EVNDRDY1" && self.phase == Phase::PreparingDriver => {
                self.prepared = true;
                self.phase = Phase::WaitingService;
                Ok(())
            }
            (Node::Service, b)
                if b == *b"EVNSWAIT" && self.phase == Phase::WaitingService && self.prepared =>
            {
                self.waiting = true;
                self.phase = Phase::WaitingEntropy;
                Ok(())
            }
            (Node::Service, b)
                if b == *b"EVNSRDY1" && self.phase == Phase::Initializing && self.initialized =>
            {
                self.phase = Phase::Running;
                Ok(())
            }
            _ => {
                self.phase = Phase::Unavailable;
                Err(Error::Event)
            }
        }
    }
    pub fn expire(&mut self, now: u64) -> Result<(), Error> {
        self.observe(now)?;
        if self.phase == Phase::Unavailable {
            return Err(Error::State);
        }
        if matches!(
            self.phase,
            Phase::PreparingDriver
                | Phase::WaitingService
                | Phase::Initializing
                | Phase::ShuttingDown
        ) && now >= self.cut
        {
            self.phase = Phase::Unavailable;
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub fn stopped(&mut self, node: Node, actor: Identity) -> Result<(), Error> {
        if self.actors[node.index()] != Some(actor) {
            return Err(Error::Identity);
        }
        if !matches!(self.phase, Phase::HardwareStopped | Phase::Stopped) {
            self.phase = Phase::Unavailable;
        }
        Ok(())
    }
    pub fn reported(&self, node: Node) -> bool {
        self.reported[node.index()]
    }
    fn operation(&mut self, now: u64, cut: u64) -> Result<(), Error> {
        self.observe(now)?;
        if cut == u64::MAX || cut <= now || cut - now > 1024 {
            return Err(Error::Clock);
        }
        self.cut = cut;
        Ok(())
    }
    pub fn initialize(&mut self, now: u64, cut: u64) -> Result<(), Error> {
        if self.phase != Phase::WaitingEntropy {
            return Err(Error::State);
        }
        self.operation(now, cut)?;
        self.phase = Phase::Initializing;
        Ok(())
    }
    pub fn initialized(&mut self, actor: Identity, now: u64) -> Result<(), Error> {
        self.expire(now)?;
        if self.phase != Phase::Initializing
            || self.initialized
            || self.actors[Node::Service.index()] != Some(actor)
        {
            return Err(Error::Identity);
        }
        self.initialized = true;
        Ok(())
    }
    pub fn begin_shutdown(&mut self, now: u64, cut: u64) -> Result<(), Error> {
        if !matches!(self.phase, Phase::WaitingEntropy | Phase::Running) {
            return Err(Error::State);
        }
        self.operation(now, cut)?;
        self.phase = Phase::ShuttingDown;
        Ok(())
    }
    /// One explicit bulk-retirement transaction, separate from legacy single
    /// 1024-tick operation semantics. It cannot be renewed while in progress.
    pub fn begin_shutdown_v2(&mut self, now: u64, cut: u64) -> Result<(), Error> {
        if !matches!(self.phase, Phase::WaitingEntropy | Phase::Running) {
            return Err(Error::State);
        }
        self.observe(now)?;
        if cut == u64::MAX || cut <= now || cut - now > 8192 {
            return Err(Error::Expired);
        }
        self.cut = cut;
        self.phase = Phase::ShuttingDown;
        Ok(())
    }
    /// Only a fully joined protected service reply, after its actual Driver
    /// Stop/scrub/readback ACK, may clear hardware debt. CPU STOP still follows.
    pub fn hardware_stopped(&mut self, actor: Identity, now: u64) -> Result<(), Error> {
        self.expire(now)?;
        if self.phase != Phase::ShuttingDown || self.actors[Node::Service.index()] != Some(actor) {
            return Err(Error::Identity);
        }
        self.phase = Phase::HardwareStopped;
        Ok(())
    }
    pub fn fail(&mut self) {
        self.phase = Phase::Unavailable;
    }
    pub fn cpus_stopped(&mut self, now: u64) -> Result<(), Error> {
        self.observe(now)?;
        if self.phase != Phase::HardwareStopped {
            return Err(Error::State);
        }
        self.phase = Phase::Stopped;
        Ok(())
    }
    pub fn shutdown_complete(&self) -> bool {
        self.phase == Phase::Stopped
    }
    /// Actual captured-Root exclusion joined before physical work, then the
    /// same stopped pair/token is rechecked by the sealed completion adapter.
    /// Consume the actual physical witness before invoking that adapter; an
    /// unsuccessful Core join keeps this state Unavailable, with no fake Stop.
    pub fn recovered(
        &mut self,
        stopped: ev_net_driver::device::recovery::Stopped<ev_net_driver::mediated::Mediated>,
        now: u64,
        join: impl FnOnce() -> bool,
    ) -> Result<(), Error> {
        self.observe(now)?;
        if self.phase != Phase::Unavailable || stopped.bytes() != 16384 {
            return Err(Error::State);
        }
        if !join() {
            return Err(Error::State);
        }
        self.phase = Phase::Stopped;
        Ok(())
    }
    /// Recovery never starts either NIC actor. Exiting that exact empty graph
    /// needs no device stop receipt and does not manufacture a Stopped phase.
    /// The runtime supplies presence from its actual child slots.
    pub fn recovery_without_start(
        &self,
        mode: ev_userspace_contract::root_v2::native::catalogue::BootMode,
        actual_actors: [bool; 2],
    ) -> bool {
        mode == ev_userspace_contract::root_v2::native::catalogue::BootMode::Recovery
            && self.phase == Phase::Unstarted
            && self.actors.iter().all(Option::is_none)
            && actual_actors == [false; 2]
    }
    pub fn mark_reported(&mut self, node: Node) {
        self.reported[node.index()] = true;
    }
    /// Startup Ready proves its bounded prepare, not the future shutdown of a
    /// live device graph. No CPU exit, timeout or metadata flag clears this debt.
    pub fn hardware_debt(&self) -> bool {
        !matches!(
            self.phase,
            Phase::Unstarted | Phase::HardwareStopped | Phase::Stopped
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn actor(n: u64) -> Identity {
        Identity {
            control: n,
            process: n + 10,
            thread: n + 20,
        }
    }
    #[test]
    fn recovery_exit_requires_the_actual_unstarted_graph_without_a_fake_stop() {
        use ev_userspace_contract::root_v2::native::catalogue::BootMode;
        let mut state = State::new();
        assert!(state.recovery_without_start(BootMode::Recovery, [false; 2]));
        assert_eq!(state.phase(), Phase::Unstarted);
        assert!(!state.shutdown_complete());
        assert!(!state.hardware_debt());
        for mode in [BootMode::Standalone, BootMode::SystemManaged] {
            assert!(!state.recovery_without_start(mode, [false; 2]));
        }
        for present in [[true, false], [false, true], [true, true]] {
            assert!(!state.recovery_without_start(BootMode::Recovery, present));
        }
        state.begin(10, 100).unwrap();
        assert!(!state.recovery_without_start(BootMode::Recovery, [false; 2]));
        assert!(state.hardware_debt());
        state.fail();
        assert!(!state.recovery_without_start(BootMode::Recovery, [false; 2]));
        assert!(state.hardware_debt());
    }
    #[test]
    fn actual_prepared_and_waiting_are_distinct_from_seeded_ready_or_shutdown() {
        let mut s = State::new();
        s.begin(5, 8197).unwrap();
        s.bind(Node::Driver, actor(1)).unwrap();
        s.event(Node::Driver, actor(1), *b"EVNDRDY1", 6).unwrap();
        assert!(s.prepared() && !s.waiting() && s.hardware_debt());
        s.bind(Node::Service, actor(2)).unwrap();
        s.event(Node::Service, actor(2), *b"EVNSWAIT", 7).unwrap();
        assert_eq!(s.phase(), Phase::WaitingEntropy);
        assert!(s.waiting() && s.hardware_debt());
        s.expire(99999).unwrap();
        assert_eq!(
            s.event(Node::Service, actor(2), *b"EVNSRDY1", 100000),
            Err(Error::Event)
        );
        assert!(s.unavailable() && s.hardware_debt());
    }
    #[test]
    fn wrong_identity_late_prepare_and_rollback_cannot_restore_availability() {
        let mut s = State::new();
        s.begin(10, 20).unwrap();
        s.bind(Node::Driver, actor(1)).unwrap();
        assert_eq!(
            s.event(Node::Driver, actor(2), *b"EVNDRDY1", 11),
            Err(Error::Identity)
        );
        assert_eq!(
            s.event(Node::Driver, actor(1), *b"EVNDRDY1", 20),
            Err(Error::Expired)
        );
        assert_eq!(
            s.event(Node::Driver, actor(1), *b"EVNDRDY1", 19),
            Err(Error::Clock)
        );
        assert!(!s.prepared() && s.unavailable() && s.hardware_debt());
    }
    #[test]
    fn refused_begin_observes_clock_and_zero_alias_or_stale_stop_cannot_join() {
        let mut s = State::new();
        assert_eq!(s.begin(50, 50), Err(Error::Clock));
        assert_eq!(s.begin(49, 60), Err(Error::Clock));
        let mut s = State::new();
        s.begin(1, 100).unwrap();
        s.bind(Node::Driver, actor(1)).unwrap();
        assert_eq!(s.bind(Node::Service, actor(1)), Err(Error::Identity));
        assert_eq!(s.stopped(Node::Driver, actor(2)), Err(Error::Identity));
        s.stopped(Node::Driver, actor(1)).unwrap();
        assert!(s.hardware_debt());
        s.mark_reported(Node::Driver);
        assert!(s.reported(Node::Driver));
    }
    fn waiting() -> State {
        let mut s = State::new();
        s.begin(1, 100).unwrap();
        s.bind(Node::Driver, actor(1)).unwrap();
        s.event(Node::Driver, actor(1), *b"EVNDRDY1", 2).unwrap();
        s.bind(Node::Service, actor(2)).unwrap();
        s.event(Node::Service, actor(2), *b"EVNSWAIT", 3).unwrap();
        s
    }
    #[test]
    fn qualified_ack_and_actual_ready_are_both_required_then_real_hardware_and_cpu_stop() {
        let mut s = waiting();
        s.initialize(4, 100).unwrap();
        s.initialized(actor(2), 5).unwrap();
        assert_eq!(s.phase(), Phase::Initializing);
        assert!(s.hardware_debt());
        assert_eq!(s.initialized(actor(2), 6), Err(Error::Identity));
        s.event(Node::Service, actor(2), *b"EVNSRDY1", 7).unwrap();
        assert_eq!(s.phase(), Phase::Running);
        s.begin_shutdown(8, 100).unwrap();
        assert!(s.hardware_debt());
        assert_eq!(s.hardware_stopped(actor(1), 9), Err(Error::Identity));
        s.hardware_stopped(actor(2), 10).unwrap();
        assert!(!s.hardware_debt());
        assert!(!s.shutdown_complete());
        s.stopped(Node::Driver, actor(1)).unwrap();
        s.cpus_stopped(11).unwrap();
        assert!(s.shutdown_complete());
    }
    #[test]
    fn unacknowledged_ready_and_expired_stop_or_cpu_death_never_clear_hardware_debt() {
        let mut s = waiting();
        s.initialize(4, 100).unwrap();
        assert_eq!(
            s.event(Node::Service, actor(2), *b"EVNSRDY1", 5),
            Err(Error::Event)
        );
        assert!(s.hardware_debt());
        let mut s = waiting();
        s.begin_shutdown(4, 10).unwrap();
        assert_eq!(s.hardware_stopped(actor(2), 10), Err(Error::Expired));
        assert!(s.hardware_debt() && !s.shutdown_complete());
        let mut s = waiting();
        s.stopped(Node::Service, actor(2)).unwrap();
        assert!(s.hardware_debt() && !s.shutdown_complete());
    }
    #[test]
    fn shutdown_v2_has_one_nonrenewable_bulk_cut_and_never_confuses_progress_with_quiescence() {
        let mut s = waiting();
        s.begin_shutdown_v2(4, 8196).unwrap();
        assert!(s.hardware_debt());
        assert!(!s.shutdown_complete());
        assert_eq!(s.begin_shutdown_v2(5, 8197), Err(Error::State));
        assert_eq!(s.hardware_stopped(actor(99), 5), Err(Error::Identity));
        assert!(s.hardware_debt());
        assert_eq!(s.hardware_stopped(actor(2), 8196), Err(Error::Expired));
        assert!(s.hardware_debt());
        for cut in [4, 8197, u64::MAX] {
            let mut s = waiting();
            assert_eq!(s.begin_shutdown_v2(4, cut), Err(Error::Expired));
            assert!(s.hardware_debt());
        }
        let mut s = waiting();
        s.begin_shutdown_v2(4, 8196).unwrap();
        assert!(s.hardware_stopped(actor(2), 3).is_err());
        assert!(s.hardware_debt());
        let mut s = waiting();
        s.begin_shutdown_v2(4, 8196).unwrap();
        s.hardware_stopped(actor(2), 8000).unwrap();
        assert!(!s.hardware_debt());
        assert!(!s.shutdown_complete());
        s.cpus_stopped(8001).unwrap();
        assert!(s.shutdown_complete());
    }
}

pub mod time_exchange;
