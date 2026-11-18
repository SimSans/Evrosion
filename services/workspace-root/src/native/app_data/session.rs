//! Actual captured RootEvents ND handler and separate immutable reply owner.
use super::super::*;
use super::NativeOwner;
use ev_workspace_root::app_data::{
    Phase,
    descriptor::Descriptor,
    session::{self as model, Admission, Enrollment, Session, Target},
};

pub(crate) struct State {
    owner: Option<NativeOwner>,
    session: Session,
    enrollment_attempt: Option<(Enrollment, u64)>,
}
impl State {
    pub(in crate::native) fn enroll_held(
        &mut self,
        child: Child,
        held: Actor,
        descriptor: Descriptor,
        checked_package: &ev_workspace_root::requirements::Checked<'_>,
        boot_epoch: u64,
        original_cut: u64,
    ) -> Result<(), ()> {
        if !self.ready() {
            return Err(());
        }
        let enrollment = Enrollment::captured(
            child,
            held,
            descriptor,
            checked_package.package(),
            boot_epoch,
        )
        .ok_or(())?;
        let tick = now();
        self.session
            .can_enroll(enrollment, tick, original_cut)
            .map_err(|_| ())?;
        if !matches_control(enrollment.target, true) {
            return Err(());
        }
        // Retain exact attempted namespace/held owner/cut before cold recovery
        // can touch storage. A failed open cannot be reconstructed or retried.
        self.enrollment_attempt = Some((enrollment, original_cut));
        let owner = self.owner.as_mut().ok_or(())?;
        let value = {
            let opened = owner.open_app_data_checked(
                descriptor.data(),
                ev_workspace_root::app_data::Access::ReadWrite,
                original_cut,
            );
            let mut data = match opened {
                Ok(data) => data,
                Err(_) => {
                    self.session.fence();
                    return Err(());
                }
            };
            data.read(original_cut).map_err(|_| ())
        };
        let value = match value {
            Ok(value) => value,
            Err(()) => {
                self.session.fence();
                return Err(());
            }
        };
        if !matches_control(enrollment.target, true) {
            self.session.fence();
            return Err(());
        }
        let enrolled = self
            .session
            .enroll(enrollment, value, now(), original_cut)
            .map_err(|_| ());
        if enrolled.is_ok() {
            self.enrollment_attempt = None;
        }
        enrolled
    }
    pub(in crate::native) fn development_owner(&mut self) -> Result<&mut NativeOwner, ()> {
        if !self.ready() || !self.session.can_stop() {
            return Err(());
        }
        self.owner.as_mut().ok_or(())
    }
    pub const fn new() -> Self {
        Self {
            owner: None,
            session: Session::new(),
            enrollment_attempt: None,
        }
    }
    fn ready(&self) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|o| o.status().phase == Phase::Ready)
            && !self.session.retained()
            && self.enrollment_attempt.is_none()
    }
}
fn matches_control(target: Target, live: bool) -> bool {
    let identity = rt::call4(s::PROCESS_IDENTITY, target.control, 0, 0, 0);
    if identity.status != 0
        || identity.value != target.identity.process
        || identity.capability != target.identity.thread
        || identity.serial != 0
    {
        return false;
    }
    let state = rt::call4(s::OBSERVE, target.control, 0, 0, 0);
    state.status == 0
        && state.capability == 0
        && state.serial == 0
        && state.value == u64::from(!live)
}
impl Root<'_> {
    pub(in crate::native) fn app_data_claim(&mut self) {
        require(self.private_data.owner.is_none(), 1710);
        // SAFETY: actual once-admitted Root bootstrap at509; boot has created
        // and retained the SystemBlock endpoint and awaited actual Block Ready.
        // This is the sole Root508 owner; no event pump runs while borrowed.
        let owner = unsafe {
            NativeOwner::claim_from_admitted_root(
                &self.bootstrap,
                self.channel(Channel::SystemBlock),
            )
        }
        .unwrap_or_else(|_| rt::exit(1711));
        let source = owner.source();
        require(
            source.process == self.bootstrap.context().process
                && source.incarnation == self.bootstrap.context().incarnation
                && source.boot_epoch == self.bootstrap.context().epoch
                && source.system_io_handle == self.bootstrap.handle(Role::SystemIo)
                && source.system_block_handle == self.channel(Channel::SystemBlock),
            1712,
        );
        self.private_data.owner = Some(owner);
    }
    /// Private installer seam. Caller has independently obtained protected
    /// enrollment permission and holds this exact newly created, unstarted
    /// FileApp6 actor; it must not START on any refusal. This never formats.
    /// No startup actor is enrolled merely from its catalogue/package claim.
    #[allow(dead_code)] // Protected install/run consumer is a separate pending join.
    pub(in crate::native) fn app_data_enroll_held(
        &mut self,
        child: Child,
        held: Actor,
        descriptor: Descriptor,
        checked_package: &ev_workspace_root::requirements::Checked<'_>,
        original_cut: u64,
    ) -> Result<(), ()> {
        if self.shutdown.active() {
            return Err(());
        }
        self.private_data.enroll_held(
            child,
            held,
            descriptor,
            checked_package,
            self.bootstrap.context().epoch,
            original_cut,
        )
    }
    /// Actual loaded handler/window availability only. Permission and original
    /// allocation still require independent enrollment before START.
    #[allow(dead_code)] // Consulted by the separately joined private installer.
    pub(in crate::native) fn app_data_available(&self) -> bool {
        self.private_data.ready()
    }
    pub(in crate::native) fn app_data_receive_ready(&mut self) -> bool {
        self.app_data_flush();
        self.private_data.session.receive_ready()
    }
    pub(in crate::native) fn app_data_events_empty(&mut self) {
        if self.private_data.session.events_empty(now()).is_err() {
            self.private_data.session.fence();
        }
    }
    pub(in crate::native) fn app_data_event(&mut self, child: Child, bytes: [u8; 8]) {
        let Some(actor) = self.actors[child.index()] else {
            return;
        };
        let Some(target) = Target::captured(child, actor) else {
            return;
        };
        let work = match self.private_data.session.accept(target, bytes, now()) {
            Ok(Admission::Work(work)) => work,
            Ok(Admission::ReplyReserved | Admission::RetiredFrameDrained) => {
                self.app_data_flush();
                return;
            }
            Err(_) => {
                self.private_data.session.fence();
                return;
            }
        };
        if !self.private_data.ready() || !matches_control(target, true) {
            self.private_data.session.storage_failed(None);
            self.app_data_flush();
            return;
        }
        // No receive, lifecycle or display pump may reenter this exclusive
        // actual508 window while checked namespace recovery/read/write runs.
        let outcome = model::execute(&mut self.private_data.owner.as_mut().unwrap().owner, work);
        match outcome {
            Ok(value) => {
                if !matches_control(target, true)
                    || self
                        .private_data
                        .session
                        .completed(work, value, now())
                        .is_err()
                {
                    self.private_data.session.storage_failed(None);
                }
            }
            Err(failure) => self.private_data.session.storage_failed(failure.pending),
        }
        self.app_data_flush();
    }
    pub(in crate::native) fn app_data_flush(&mut self) {
        let Ok(Some(reply)) = self.private_data.session.reply(now()) else {
            return;
        };
        let actual = self.actors[reply.target.child.index()]
            .and_then(|a| Target::captured(reply.target.child, a));
        if actual != Some(reply.target) || !matches_control(reply.target, true) {
            let _ = self
                .private_data
                .session
                .sent(reply, model::SendResult::Unknown, now());
            return;
        }
        let Some(channel) = control_channel(reply.target.child) else {
            self.private_data.session.fence();
            return;
        };
        let result = rt::call4(
            s::SEND,
            self.channel(channel),
            u64::from_le_bytes(reply.bytes),
            0,
            0,
        );
        let result = if result.value != 0 || result.capability != 0 || result.serial != 0 {
            model::SendResult::Unknown
        } else {
            match result.status {
                0 => model::SendResult::Accepted,
                2 => model::SendResult::WouldBlock,
                _ => model::SendResult::Unknown,
            }
        };
        let _ = self.private_data.session.sent(reply, result, now());
    }
    pub(in crate::native) fn app_data_can_stop(&self) -> bool {
        self.private_data.ready() && self.private_data.session.can_stop()
    }
    pub(in crate::native) fn app_data_seal(&mut self, cut: u64) -> Result<(), ()> {
        if !self.private_data.ready() {
            return Err(());
        }
        self.private_data.session.seal(now(), cut).map_err(|_| ())
    }
    pub(in crate::native) fn app_data_stopped(
        &mut self,
        target: ev_workspace_root::shutdown::Target,
    ) -> Result<(), ()> {
        let Some(enrollment) = self.private_data.session.enrollment() else {
            return Ok(());
        };
        if target.child != enrollment.target.child {
            return Ok(());
        }
        if target.control != enrollment.target.control
            || target.identity != enrollment.target.identity
            || !matches_control(enrollment.target, false)
        {
            return Err(());
        }
        self.private_data
            .session
            .stopped(enrollment.target, now())
            .map_err(|_| ())
    }
    pub(in crate::native) fn app_data_quiescent(&self) -> bool {
        self.private_data.ready() && self.private_data.session.quiescent()
    }
}
