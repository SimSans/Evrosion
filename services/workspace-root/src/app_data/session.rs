//! Finite ND ownership beside actual native capabilities. Metadata is never
//! enrollment authority, ProcessCONTROL liveness, or an accepted SEND receipt.
use super::{Access, Owner, descriptor::Descriptor, private_data};
use crate::{Actor, Identity};
use ev_app_registry::app_data::AppDataEnvelope;
use ev_block_service::store_io::{Window, Wire};
use ev_userspace_contract::{app_data as wire, root_v5::graph::Child};
use ev_zion::{Capability, Package};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub child: Child,
    pub control: u64,
    pub identity: Identity,
    pub mapping_epoch: u32,
}
impl Target {
    pub fn captured(child: Child, actor: Actor) -> Option<Self> {
        (matches!(child, Child::EditorOne | Child::EditorTwo)
            && actor.identity.valid()
            && !matches!(actor.control, 0 | u64::MAX)
            && !matches!(actor.mapping_epoch, 0 | u32::MAX))
        .then_some(Self {
            child,
            control: actor.control,
            identity: actor.identity,
            mapping_epoch: actor.mapping_epoch,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enrollment {
    pub target: Target,
    pub descriptor: Descriptor,
    pub package: [u8; 32],
    pub image: [u8; 32],
    pub boot_epoch: u64,
}
impl Enrollment {
    /// Correlates caller-supplied original allocation and actual held facts
    /// with parsed immutable bytes. Native code must independently establish
    /// protected enrollment permission, real held control and before-START use.
    pub fn captured(
        child: Child,
        held: Actor,
        descriptor: Descriptor,
        package: &Package<'_>,
        boot_epoch: u64,
    ) -> Option<Self> {
        let target = Target::captured(child, held)?;
        if held.ready
            || held.failed
            || matches!(boot_epoch, 0 | u64::MAX)
            || package.app().claimed_app != descriptor.app()
            || !package.app().data_schema.reads(descriptor.schema_epoch())
            || !package
                .app()
                .capability_requests()
                .any(|r| r.required && r.capability == Capability::AppPrivateData)
            || !package.app().contracts().any(|r| {
                r.name == wire::INTERFACE
                    && r.major == u16::from(wire::VERSION)
                    && r.minimum_minor == 0
                    && r.features == 0
            })
        {
            return None;
        }
        Some(Self {
            target,
            descriptor,
            package: package.id().bytes(),
            image: package.executable().digest,
            boot_epoch,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    State,
    Deadline,
    Retained,
    Readback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Empty,
    Initial,
    Read,
    Set,
    Refused,
    Retired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Work {
    pub enrollment: Enrollment,
    pub request: wire::Request,
    pub original_cut: u64,
    pub before: AppDataEnvelope,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub target: Target,
    pub bytes: [u8; 8],
    pub original_cut: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendResult {
    Accepted,
    WouldBlock,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Work(Work),
    ReplyReserved,
    /// Old stopped sender's already accepted frame has actually been received.
    /// It executes no storage and is no successful application reply.
    RetiredFrameDrained,
}
#[derive(Clone, Copy)]
struct Retirement {
    cut: u64,
    stopped: bool,
}
/// One allocation, one finite Read→optional changed Set per incarnation. The
/// independent reply reservation cannot coalesce with or fall out of UI queues.
pub struct Session {
    enrollment: Option<Enrollment>,
    allocation: Option<Descriptor>,
    phase: Phase,
    cut: u64,
    last: u64,
    value: Option<AppDataEnvelope>,
    work: Option<Work>,
    reply: Option<Reply>,
    reply_unknown: bool,
    after_reply: Option<Phase>,
    accepted_replies: u8,
    pending: Option<private_data::Pending>,
    fenced: bool,
    retirement: Option<Retirement>,
    retired: Option<Target>,
}
impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}
impl Session {
    pub const fn new() -> Self {
        Self {
            enrollment: None,
            allocation: None,
            phase: Phase::Empty,
            cut: 0,
            last: 0,
            value: None,
            work: None,
            reply: None,
            reply_unknown: false,
            after_reply: None,
            accepted_replies: 0,
            pending: None,
            fenced: false,
            retirement: None,
            retired: None,
        }
    }
    pub const fn enrollment(&self) -> Option<Enrollment> {
        self.enrollment
    }
    pub const fn pending(&self) -> Option<private_data::Pending> {
        self.pending
    }
    pub const fn work(&self) -> Option<Work> {
        self.work
    }
    pub const fn retained(&self) -> bool {
        self.fenced
    }
    pub fn fence(&mut self) {
        self.fenced = true;
    }
    pub const fn receive_ready(&self) -> bool {
        self.reply.is_none()
    }
    pub const fn has_reply(&self) -> bool {
        self.reply.is_some()
    }
    pub fn can_enroll(&self, next: Enrollment, now: u64, cut: u64) -> Result<(), Error> {
        if self.fenced || self.work.is_some() || self.reply.is_some() {
            return Err(Error::Retained);
        }
        if !matches!(self.phase, Phase::Empty | Phase::Retired) || self.retirement.is_some() {
            return Err(Error::State);
        }
        if now < self.last
            || now == u64::MAX
            || cut <= now
            || cut == u64::MAX
            || cut - now > crate::shutdown::TICKS
        {
            return Err(Error::Deadline);
        }
        if self.allocation.is_some_and(|d| d != next.descriptor)
            || self.retired.is_some_and(|old| {
                old.identity == next.target.identity || old.control == next.target.control
            })
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
    pub fn enroll(
        &mut self,
        next: Enrollment,
        value: AppDataEnvelope,
        now: u64,
        cut: u64,
    ) -> Result<(), Error> {
        self.can_enroll(next, now, cut)?;
        if value.app() != next.descriptor.app()
            || value.schema_epoch() != next.descriptor.schema_epoch()
        {
            return Err(Error::Identity);
        }
        self.enrollment = Some(next);
        self.allocation = Some(next.descriptor);
        self.phase = Phase::Initial;
        self.cut = cut;
        self.last = now;
        self.value = Some(value);
        self.accepted_replies = 0;
        self.retirement = None;
        Ok(())
    }
    fn live(&mut self, now: u64, cut: u64) -> Result<(), Error> {
        if now < self.last || now == u64::MAX || now >= cut {
            self.fenced = true;
            return Err(Error::Deadline);
        }
        self.last = now;
        Ok(())
    }
    fn refuse(&mut self, target: Target, reason: wire::Refusal, cut: u64) {
        self.reply = Some(Reply {
            target,
            bytes: wire::Response::Refused(reason).encode(),
            original_cut: cut,
        });
        self.after_reply = None;
    }
    /// The native receiver has already captured this actual sender/control.
    /// Reserve immutable reply ownership BEFORE returning any executable work.
    pub fn accept(&mut self, target: Target, bytes: [u8; 8], now: u64) -> Result<Admission, Error> {
        if self.reply.is_some() {
            return Err(Error::Retained);
        }
        if let Some(retirement) = self.retirement
            && self.enrollment.is_some_and(|e| e.target == target)
        {
            self.live(now, retirement.cut)?;
            if retirement.stopped {
                return Ok(Admission::RetiredFrameDrained);
            }
            self.refuse(target, wire::Refusal::Busy, retirement.cut);
            return Ok(Admission::ReplyReserved);
        }
        let denial_cut = now
            .checked_add(crate::shutdown::TICKS)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Deadline)?;
        let Some(enrollment) = self.enrollment.filter(|e| e.target == target) else {
            self.refuse(target, wire::Refusal::Denied, denial_cut);
            return Ok(Admission::ReplyReserved);
        };
        self.live(now, self.cut)?;
        if self.fenced || self.work.is_some() || self.retirement.is_some() {
            self.refuse(target, wire::Refusal::Busy, self.cut);
            return Ok(Admission::ReplyReserved);
        }
        let request = match wire::Request::decode(&bytes, 0) {
            Ok(r) => r,
            Err(_) => {
                self.phase = Phase::Refused;
                self.refuse(target, wire::Refusal::Malformed, self.cut);
                return Ok(Admission::ReplyReserved);
            }
        };
        let valid = matches!((self.phase, request), (Phase::Initial, wire::Request::Read))
            || matches!((self.phase, request), (Phase::Read, wire::Request::SetValue(value))
                if self.value.is_some_and(|old| old.value() != value));
        if !valid {
            self.phase = Phase::Refused;
            self.refuse(target, wire::Refusal::Denied, self.cut);
            return Ok(Admission::ReplyReserved);
        }
        let work = Work {
            enrollment,
            request,
            original_cut: self.cut,
            before: self.value.ok_or(Error::State)?,
        };
        self.work = Some(work);
        self.refuse(target, wire::Refusal::Storage, self.cut);
        Ok(Admission::Work(work))
    }
    pub fn completed(&mut self, work: Work, value: AppDataEnvelope, now: u64) -> Result<(), Error> {
        if self.work != Some(work) || self.reply.is_none() {
            self.fenced = true;
            return Err(Error::Identity);
        }
        self.live(now, work.original_cut)?;
        let expected = match work.request {
            wire::Request::Read => work.before,
            wire::Request::SetValue(next) => work
                .before
                .checked_replace(
                    work.enrollment.descriptor.app(),
                    work.enrollment.descriptor.schema_epoch(),
                    work.before.counter(),
                    next,
                )
                .map_err(|_| Error::Readback)?,
        };
        if value != expected {
            self.fenced = true;
            return Err(Error::Readback);
        }
        self.reply.as_mut().unwrap().bytes = wire::Response::Value(value.value()).encode();
        self.value = Some(value);
        self.work = None;
        self.after_reply = Some(match work.request {
            wire::Request::Read => Phase::Read,
            wire::Request::SetValue(_) => Phase::Set,
        });
        Ok(())
    }
    pub fn storage_failed(&mut self, pending: Option<private_data::Pending>) {
        self.pending = pending;
        self.fenced = true;
        // Keep exact Work, original cut, and already reserved Storage refusal.
    }
    pub fn reply(&mut self, now: u64) -> Result<Option<Reply>, Error> {
        if self.reply_unknown {
            return Err(Error::Retained);
        }
        let Some(reply) = self.reply else {
            return Ok(None);
        };
        self.live(now, reply.original_cut)?;
        Ok(Some(reply))
    }
    pub fn sent(&mut self, exact: Reply, result: SendResult, now: u64) -> Result<(), Error> {
        if self.reply != Some(exact) {
            self.fenced = true;
            return Err(Error::Identity);
        }
        self.live(now, exact.original_cut)?;
        match result {
            SendResult::WouldBlock => (),
            SendResult::Unknown => {
                self.reply_unknown = true;
                self.fenced = true;
                return Err(Error::Retained);
            }
            SendResult::Accepted => {
                self.reply = None;
                if let Some(phase) = self.after_reply.take() {
                    self.phase = phase;
                    self.accepted_replies += 1;
                }
            }
        }
        Ok(())
    }
    pub fn can_stop(&self) -> bool {
        !self.fenced && self.work.is_none() && self.reply.is_none() && self.pending.is_none()
    }
    pub fn seal(&mut self, now: u64, cut: u64) -> Result<(), Error> {
        if !self.can_stop() {
            return Err(Error::Retained);
        }
        // No ND owner exists for the built-in Editor replaced by the first
        // external Run. Its actual STOP/RootEvents barrier remains the native
        // installer's obligation; inventing a private-data retirement here
        // would permanently block that first held enrollment.
        if self.enrollment.is_none() {
            return Ok(());
        }
        if let Some(old) = self.retirement {
            return if old.cut == cut {
                self.live(now, cut)
            } else {
                Err(Error::Identity)
            };
        }
        if cut == u64::MAX || cut <= now || cut - now > crate::shutdown::TICKS {
            return Err(Error::Deadline);
        }
        self.live(now, cut)?;
        self.retirement = Some(Retirement {
            cut,
            stopped: false,
        });
        Ok(())
    }
    /// Supply only AFTER exact actual Kernel STOP succeeded for the held target.
    /// STOP closes/reclaims its RootControl queued scalar replies; it is not
    /// proof the app consumed a Value and does not settle unknown storage.
    pub fn stopped(&mut self, exact: Target, now: u64) -> Result<(), Error> {
        if !self.can_stop() || self.enrollment.is_none_or(|e| e.target != exact) {
            return Err(Error::Identity);
        }
        let retirement = self.retirement.ok_or(Error::State)?;
        self.live(now, retirement.cut)?;
        self.retirement.as_mut().unwrap().stopped = true;
        self.accepted_replies = 0;
        Ok(())
    }
    /// Actual RootEvents status2 after STOP proves no old accepted request
    /// remains queued. No next incarnation can start before this barrier.
    pub fn events_empty(&mut self, now: u64) -> Result<(), Error> {
        let Some(retirement) = self.retirement else {
            return Ok(());
        };
        if self.enrollment.is_none() {
            return Ok(());
        }
        if !retirement.stopped || !self.can_stop() {
            return Ok(());
        }
        self.live(now, retirement.cut)?;
        self.retired = self.enrollment.take().map(|e| e.target);
        self.phase = Phase::Retired;
        self.retirement = None;
        Ok(())
    }
    pub fn quiescent(&self) -> bool {
        self.can_stop() && self.enrollment.is_none()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct StorageFailure<E> {
    pub pending: Option<private_data::Pending>,
    pub error: private_data::Error<super::Error<E>>,
}
/// Actual checked namespace access under the Work's unchanged original cut.
/// No format fallback, raw namespace selector, event pump or writer escapes.
#[inline(never)]
pub fn execute<T: Wire, W: Window>(
    owner: &mut Owner<T, W>,
    work: Work,
) -> Result<AppDataEnvelope, StorageFailure<T::Error>> {
    let mut data = owner
        .open_app_data_checked(
            work.enrollment.descriptor.data(),
            Access::ReadWrite,
            work.original_cut,
        )
        .map_err(|rejected| StorageFailure {
            pending: None,
            error: private_data::Error::Store(rejected.error),
        })?;
    let result = match work.request {
        wire::Request::Read => data.read(work.original_cut),
        wire::Request::SetValue(value) => match data.read(work.original_cut) {
            Ok(before) if before == work.before => {
                data.replace(work.before.counter(), value, work.original_cut)
            }
            Ok(_) => Err(private_data::Error::Readback),
            Err(error) => Err(error),
        },
    };
    result.map_err(|error| StorageFailure {
        pending: data.pending(),
        error,
    })
}
