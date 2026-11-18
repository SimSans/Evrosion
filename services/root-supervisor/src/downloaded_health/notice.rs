//! One cosmetic completion from the actual required subject. It is not startup
//! evidence, authority, a health receipt, or permission to skip a UI fence.
use super::Cohort;
use crate::native_plan::state::Identity;
use crate::native_sources::Source;
use ev_desktop::protocol::RootControl;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Subject {
    control: u64,
    identity: Identity,
    source: Source,
    package: [u8; 32],
    epoch: u32,
}
impl Subject {
    /// Root supplies only actual current actor metadata and the retained checked
    /// cohort. No ID, package, epoch or source is decoded from EVGADON1.
    #[inline(never)]
    pub fn checked(
        cohort: &Cohort,
        source: Source,
        identity: Identity,
        control: u64,
        epoch: u32,
    ) -> Option<Self> {
        let Source::Downloaded(slot) = source else {
            return None;
        };
        if control == 0
            || identity.process == 0
            || identity.thread == 0
            || epoch == 0
            || epoch == u32::MAX
            || slot.version() != cohort.content().version
        {
            return None;
        }
        Some(Self {
            control,
            identity,
            source,
            package: cohort.content().package,
            epoch,
        })
    }
    #[inline(never)]
    fn same(self, other: Self) -> bool {
        self == other
    }
}
#[derive(Clone, Copy)]
struct Notice {
    subject: Subject,
    restored: bool,
    released: bool,
}
pub struct Pending {
    notice: Option<Notice>,
}
impl Default for Pending {
    fn default() -> Self {
        Self::new()
    }
}
impl Pending {
    pub const fn new() -> Self {
        Self { notice: None }
    }
    #[inline(never)]
    pub fn capture(&mut self, subject: Subject, restored: bool) {
        if let Some(n) = self.notice {
            if !n.subject.same(subject) {
                self.discard();
            }
            return;
        }
        self.notice = Some(Notice {
            subject,
            restored,
            released: false,
        });
    }
    pub fn pending(&self) -> bool {
        self.notice.is_some()
    }
    /// Trusted controller calls this only after actual durable System health,
    /// authenticated content KnownGood publication and session release succeed.
    #[inline(never)]
    pub fn release(&mut self, subject: Subject) {
        if let Some(n) = self.notice.as_mut() {
            if n.subject.same(subject) {
                n.released = true;
            } else {
                self.discard();
            }
        }
    }
    #[inline(never)]
    pub fn ready(&mut self, subject: Subject) -> bool {
        if self.notice.is_some_and(|n| !n.subject.same(subject)) {
            self.discard();
            return false;
        }
        self.notice.is_some_and(|n| n.released)
    }
    /// Consume once only after the controller rechecks actual actor liveness and
    /// reserves the ordinary Shell outbox credit. Delivery/settlement is normal.
    #[inline(never)]
    pub fn take(&mut self, subject: Subject) -> Option<RootControl> {
        let n = self.notice?;
        if !n.subject.same(subject) {
            self.discard();
            return None;
        }
        if !n.released {
            return None;
        }
        self.notice = None;
        Some(if n.restored {
            RootControl::AppRestored(n.subject.epoch)
        } else {
            RootControl::AppStarted(n.subject.epoch)
        })
    }
    pub fn discard(&mut self) {
        self.notice = None;
    }
}
