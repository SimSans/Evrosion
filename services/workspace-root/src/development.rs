//! One exact local-owner development source. This is unsigned package policy,
//! separate from published releases, boot health, or a persistence receipt.
use crate::{Actor, Identity, requirements::Checked};
use ev_workspace_shell::{ActionScope, ActionTarget, Effect, ProtectedKind, Rights};
use ev_zion::{Capability, Package};

pub mod storage;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    Install,
    Run,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub app: [u8; 16],
    pub package: [u8; 32],
    pub image: [u8; 32],
    pub build: [u8; 32],
    pub bytes: u64,
}
impl Source {
    pub fn of(package: &Package<'_>) -> Self {
        Self {
            app: package.app().claimed_app.bytes(),
            package: package.id().bytes(),
            image: package.executable().digest,
            build: package.app().build_id,
            bytes: package.bytes().len() as u64,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub control: u64,
    pub identity: Identity,
    pub mapping_epoch: u32,
}
impl Target {
    pub fn captured(actor: Actor) -> Option<Self> {
        (actor.identity.valid()
            && !matches!(actor.control, 0 | u64::MAX)
            && !matches!(actor.mapping_epoch, 0 | u32::MAX))
        .then_some(Self {
            control: actor.control,
            identity: actor.identity,
            mapping_epoch: actor.mapping_epoch,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub source: Source,
    pub previous: Target,
    pub root: Identity,
}
impl Facts {
    pub fn capture(package: &Checked<'_>, previous: Actor, root: Identity) -> Option<Self> {
        if !root.valid() {
            return None;
        }
        Some(Self {
            source: Source::of(package.package()),
            previous: Target::captured(previous)?,
            root,
        })
    }
    pub fn scope(self, intent: Intent) -> ActionScope {
        ActionScope {
            kind: match intent {
                Intent::Install => ProtectedKind::InstallLocalDevelopment,
                Intent::Run => ProtectedKind::RunLocalDevelopment,
            },
            requester: crate::policy::owner(self.root),
            target: ActionTarget::Package {
                app: self.source.app,
                package: self.source.package,
                image: self.source.image,
                build: self.source.build,
                recipient: crate::policy::owner(self.previous.identity),
                thread: self.previous.identity.thread,
                mapping_epoch: u64::from(self.previous.mapping_epoch),
            },
            rights: match intent {
                Intent::Install => Rights::CREATE.union(Rights::DELEGATE),
                Intent::Run => Rights::PROCESS_CONTROL.union(Rights::DELEGATE),
            },
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Binding,
    Effect,
    Capability,
    Deadline,
}
/// Actual native image-boundary admission clock. The original cut is captured
/// once; parsing and hashing do not allow a later syscall to reuse entry time.
/// A failed gate never rearms, while an independent immutable reader can remain.
pub struct Cut {
    original: u64,
    last: u64,
    fenced: bool,
}
pub struct CutFailure<T> {
    /// None means no boundary invocation occurred. Some retains the actual
    /// returned result; it must never be replaced by a claimed local reply.
    pub actual: Option<T>,
}
impl Cut {
    pub fn new(now: u64, original: u64) -> Result<Self, Error> {
        if original == u64::MAX || original <= now || original - now > crate::shutdown::TICKS {
            return Err(Error::Deadline);
        }
        Ok(Self {
            original,
            last: now,
            fenced: false,
        })
    }
    pub fn admit(&mut self, now: u64) -> Result<(), Error> {
        if self.fenced || now < self.last || now >= self.original {
            self.fenced = true;
            return Err(Error::Deadline);
        }
        self.last = now;
        Ok(())
    }
    pub fn complete(&mut self, now: u64) -> Result<(), Error> {
        self.admit(now)
    }
    pub fn invoke<T>(
        &mut self,
        mut clock: impl FnMut() -> u64,
        call: impl FnOnce() -> T,
    ) -> Result<T, CutFailure<T>> {
        self.admit(clock())
            .map_err(|_| CutFailure { actual: None })?;
        let actual = call();
        if self.complete(clock()).is_err() {
            return Err(CutFailure {
                actual: Some(actual),
            });
        }
        Ok(actual)
    }
}
/// Move-only exact protected decision; no constructor from claimed metadata,
/// normal App intent, successful START, compatibility or a digest comparison.
pub struct Approval {
    facts: Facts,
    intent: Intent,
    nonce: u64,
    first: u64,
    cut: u64,
}
impl Approval {
    pub const fn facts(&self) -> Facts {
        self.facts
    }
    pub const fn intent(&self) -> Intent {
        self.intent
    }
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
    pub const fn cut(&self) -> u64 {
        self.cut
    }
    pub fn current(&self, facts: Facts, now: u64) -> bool {
        self.facts == facts && now >= self.first && now < self.cut
    }
}
pub fn approve(
    facts: Facts,
    intent: Intent,
    effect: Effect,
    now: u64,
    cut: u64,
) -> Result<Approval, Error> {
    if cut == u64::MAX || cut <= now || cut - now > crate::shutdown::TICKS {
        return Err(Error::Deadline);
    }
    if effect.scope() != facts.scope(intent) || matches!(effect.nonce(), 0 | u64::MAX) {
        return Err(Error::Effect);
    }
    Ok(Approval {
        facts,
        intent,
        nonce: effect.nonce(),
        first: now,
        cut,
    })
}
/// Requested selected-file rights stay distinct from private-data permission.
/// Only the actual current immutable software can satisfy this check.
pub fn allows_file(package: &Package<'_>, write: bool) -> bool {
    let has = |wanted| {
        package
            .app()
            .capability_requests()
            .any(|r| r.capability == wanted)
    };
    has(Capability::SelectedFileRead) && (!write || has(Capability::SelectedFileEdit))
}
pub fn private_profile(package: &Package<'_>) -> Result<(), Error> {
    let mut read = false;
    let mut edit = false;
    let mut data = false;
    let mut surface = false;
    let mut input = false;
    for request in package.app().capability_requests() {
        match request.capability {
            Capability::SelectedFileRead => read = true,
            Capability::SelectedFileEdit => edit = true,
            Capability::AppPrivateData if request.required => data = true,
            Capability::OwnSurfacePresent => surface = true,
            Capability::FocusedInput => input = true,
            Capability::Diagnostics => {}
            Capability::UnknownOptional(_) if !request.required => (),
            _ => return Err(Error::Capability),
        }
    }
    let nd = package.app().contracts().any(|r| {
        r.name == ev_userspace_contract::app_data::INTERFACE
            && r.major == 1
            && r.minimum_minor == 0
            && r.features == 0
    });
    if !data || !nd || !surface || !input || edit && !read {
        return Err(Error::Capability);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
