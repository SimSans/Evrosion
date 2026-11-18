//! A held, non-cloneable actual-adapter issuer is distinct from ordinary model
//! messages and semantic actions. Witnesses are private, consumed and scoped to
//! one Desktop instance. This proves reducer separation, not hardware presence.
//! The integration must issue attestations only after real protected input,
//! Present completion and current endpoint/target revalidation.
use crate::{Desktop, Error, Owner, ProviderLease, ProviderRights, WindowId, next};
use core::sync::atomic::{AtomicU64, Ordering};

static BINDING: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(u16);
impl Rights {
    pub const READ: Self = Self(1);
    pub const EDIT: Self = Self(2);
    pub const CREATE: Self = Self(4);
    pub const REMOVE: Self = Self(8);
    pub const PROCESS_CONTROL: Self = Self(16);
    pub const DELEGATE: Self = Self(32);
    /// Semantic metadata, ordinary actions, document bytes and protected
    /// confirmation are four independently chosen native adapter scopes.
    pub const SEMANTIC_READ: Self = Self(64);
    pub const SEMANTIC_ACTION: Self = Self(128);
    pub const SEMANTIC_TEXT: Self = Self(256);
    pub const ASSISTIVE_CONFIRM: Self = Self(512);
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn bits(self) -> u16 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectedKind {
    PickerConsent,
    OwnerOverride,
    Revoke,
    InstallLocalDevelopment,
    RunLocalDevelopment,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionTarget {
    /// Full immutable unsigned development source and captured destination.
    /// These fields supply correlation only. Actual Root must re-resolve its
    /// held control/source before presentation and confirmation; a package
    /// claim or a syntactically valid target grants no enrollment authority.
    Package {
        app: [u8; 16],
        package: [u8; 32],
        image: [u8; 32],
        build: [u8; 32],
        recipient: Owner,
        thread: u64,
        mapping_epoch: u64,
    },
    /// The actual adapter resolves the independently owned Root control and
    /// presentation epoch. This never follows from an ordinary Window grant.
    ProtectedRoot {
        owner: Owner,
        thread: u64,
        mapping_epoch: u64,
    },
    Window {
        id: WindowId,
        owner: Owner,
    },
    /// Actual adapter re-resolves this full descriptor against the selected
    /// dataset/object route before BOTH presentation and confirmation.
    Object {
        dataset: [u8; 16],
        slot: u16,
        generation: u64,
        revision: u64,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionScope {
    pub kind: ProtectedKind,
    pub requester: Owner,
    pub target: ActionTarget,
    pub rights: Rights,
}
impl ActionScope {
    fn valid(self, desktop: &Desktop) -> Result<(), Error> {
        if !self.requester.valid() || !desktop.live_owner(self.requester) || self.rights.bits() == 0
        {
            return Err(Error::Identity);
        }
        match self.target {
            ActionTarget::Package {
                app,
                package,
                image,
                build,
                recipient,
                thread,
                mapping_epoch,
            } => {
                if app == [0; 16]
                    || [package, image, build].contains(&[0; 32])
                    || !recipient.valid()
                    || matches!(thread, 0 | u64::MAX)
                    || matches!(mapping_epoch, 0 | u64::MAX)
                    || !matches!(
                        self.kind,
                        ProtectedKind::InstallLocalDevelopment | ProtectedKind::RunLocalDevelopment
                    )
                {
                    return Err(Error::Identity);
                }
            }
            ActionTarget::ProtectedRoot {
                owner,
                thread,
                mapping_epoch,
            } => {
                if owner != desktop.control.owner()
                    || matches!(thread, 0 | u64::MAX)
                    || matches!(mapping_epoch, 0 | u64::MAX)
                {
                    return Err(Error::Owner);
                }
            }
            ActionTarget::Window { id, owner } => {
                if desktop.window(id)?.owner != owner {
                    return Err(Error::Owner);
                }
            }
            ActionTarget::Object {
                dataset,
                generation,
                revision,
                ..
            } => {
                if dataset == [0; 16]
                    || generation == 0
                    || generation == u64::MAX
                    || revision == u64::MAX
                {
                    return Err(Error::Identity);
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub attention: u64,
    pub nonce: u64,
    pub scope: ActionScope,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Presentation {
    challenge: Challenge,
    frame: u64,
    input_cut: u64,
}

/// Neither witness implements Copy/Clone or has a public constructor.
#[derive(Debug)]
pub struct AttentionWitness {
    binding: u64,
    attention: u64,
}
#[derive(Debug)]
pub struct PresentedWitness {
    binding: u64,
    presentation: Presentation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationSource {
    Physical,
    /// The trusted adapter authenticates this actual assistive sender and its
    /// deliberate fresh confirmation. A provider lease alone is insufficient.
    Assistive {
        sender: Owner,
        provider: ProviderLease,
    },
}
#[derive(Debug, PartialEq, Eq)]
pub struct Effect {
    scope: ActionScope,
    nonce: u64,
}
impl Effect {
    pub const fn scope(&self) -> ActionScope {
        self.scope
    }
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
}
#[derive(Debug)]
pub struct ProtectedSemanticView {
    pub challenge: Challenge,
    pub frame: u64,
    pub label: &'static str,
    /// These describe a separate trusted interaction, not ordinary Activate.
    pub confirm_requires_adapter_witness: bool,
}

pub(crate) struct ControlState {
    binding: u64,
    owner: Owner,
    input_serial: u64,
    attention_counter: u64,
    nonce: u64,
    frame: u64,
    attention: Option<u64>,
    pending: Option<Challenge>,
    presented: Option<Presentation>,
}
impl ControlState {
    pub(crate) fn bind(owner: Owner) -> Result<(Self, TrustedAdapter), Error> {
        let previous = BINDING
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| next(old).ok())
            .map_err(|_| Error::Exhausted)?;
        let binding = next(previous)?;
        Ok((
            Self {
                binding,
                owner,
                input_serial: 0,
                attention_counter: 0,
                nonce: 0,
                frame: 0,
                attention: None,
                pending: None,
                presented: None,
            },
            TrustedAdapter { binding, owner },
        ))
    }
    pub(crate) const fn owner(&self) -> Owner {
        self.owner
    }
    pub(crate) const fn binding(&self) -> u64 {
        self.binding
    }
    pub(crate) const fn attention(&self) -> Option<u64> {
        self.attention
    }
    pub(crate) const fn active(&self) -> bool {
        self.attention.is_some()
    }
    pub(crate) fn invalidate(&mut self) {
        self.attention = None;
        self.pending = None;
        self.presented = None;
    }
    fn fresh(&self, serial: u64) -> Result<(), Error> {
        if serial <= self.input_serial || serial == u64::MAX {
            return Err(Error::Stale);
        }
        Ok(())
    }
}

/// Keep exclusively in the actual trusted adapter. This is deliberately not
/// serializable and has no constructor other than Desktop controller setup.
pub struct TrustedAdapter {
    binding: u64,
    owner: Owner,
}
impl TrustedAdapter {
    /// The actual adapter supplies only its independently owned immutable Root
    /// surface after validating real mapping/read credit. App input cannot call
    /// this method without possessing the held issuer.
    pub fn borrow_protected<'a>(
        &self,
        desktop: &Desktop,
        bounds: crate::Rect,
        header: crate::composition::ProtectedHeader,
        pixels: &'a [u32],
    ) -> Result<crate::composition::ProtectedFrame<'a>, crate::composition::ComposeError> {
        self.check(desktop)?;
        crate::composition::ProtectedFrame::from_adapter(
            self.binding,
            desktop,
            bounds,
            header,
            pixels,
        )
    }
    fn check(&self, desktop: &Desktop) -> Result<(), Error> {
        if self.binding != desktop.control.binding || self.owner != desktop.control.owner {
            return Err(Error::Owner);
        }
        Ok(())
    }
    /// Called only after an independently routed actual trusted-attention event.
    /// No live Shell endpoint or healthy ordinary App is required.
    pub fn attest_attention(
        &mut self,
        desktop: &mut Desktop,
        input_serial: u64,
    ) -> Result<AttentionWitness, Error> {
        self.check(desktop)?;
        desktop.control.fresh(input_serial)?;
        let attention = next(desktop.control.attention_counter)?;
        desktop.available_revision()?;
        desktop.control.input_serial = input_serial;
        desktop.control.attention_counter = attention;
        desktop.control.attention = Some(attention);
        desktop.control.pending = None;
        desktop.control.presented = None;
        desktop.pending_action = None;
        desktop.advance()?;
        Ok(AttentionWitness {
            binding: self.binding,
            attention,
        })
    }
    /// `scope` must be derived from actual current object/recipient endpoints by
    /// this adapter, never copied from an untrusted request without validation.
    pub fn challenge(
        &mut self,
        desktop: &mut Desktop,
        attention: AttentionWitness,
        scope: ActionScope,
    ) -> Result<Challenge, Error> {
        self.check(desktop)?;
        if attention.binding != self.binding
            || desktop.control.attention != Some(attention.attention)
        {
            return Err(Error::Stale);
        }
        scope.valid(desktop)?;
        if desktop.control.pending.is_some() {
            return Err(Error::Unsettled);
        }
        let nonce = next(desktop.control.nonce)?;
        desktop.available_revision()?;
        let challenge = Challenge {
            attention: attention.attention,
            nonce,
            scope,
        };
        desktop.control.nonce = nonce;
        desktop.control.pending = Some(challenge);
        desktop.advance()?;
        Ok(challenge)
    }
    /// Supply the scope freshly resolved by the actual adapter again. The
    /// witness can be issued only after this exact protected frame completed,
    /// followed by a real input barrier. The actual adapter also checks released
    /// activation state; queue sequence alone cannot establish a fresh press.
    pub fn attest_presented(
        &mut self,
        desktop: &mut Desktop,
        challenge: Challenge,
        resolved_scope: ActionScope,
        frame: u64,
        input_cut: u64,
    ) -> Result<PresentedWitness, Error> {
        self.check(desktop)?;
        if desktop.control.attention != Some(challenge.attention)
            || desktop.control.pending != Some(challenge)
            || challenge.scope != resolved_scope
            || frame <= desktop.control.frame
            || frame == u64::MAX
            || input_cut < desktop.control.input_serial
            || input_cut == u64::MAX
            || desktop.control.presented.is_some()
        {
            return Err(Error::Stale);
        }
        resolved_scope.valid(desktop)?;
        desktop.available_revision()?;
        let presentation = Presentation {
            challenge,
            frame,
            input_cut,
        };
        desktop.control.input_serial = input_cut;
        desktop.control.frame = frame;
        desktop.control.presented = Some(presentation);
        desktop.advance()?;
        Ok(PresentedWitness {
            binding: self.binding,
            presentation,
        })
    }
    /// Returns a scoped request for the actual controller, NOT evidence that a
    /// kernel capability has already changed. Execution must revalidate routes.
    pub fn attest_confirmation(
        &mut self,
        desktop: &mut Desktop,
        witness: PresentedWitness,
        resolved_scope: ActionScope,
        input_serial: u64,
        source: ConfirmationSource,
    ) -> Result<Effect, Error> {
        self.check(desktop)?;
        desktop.control.fresh(input_serial)?;
        let presented = witness.presentation;
        if witness.binding != self.binding
            || desktop.control.presented != Some(presented)
            || desktop.control.pending != Some(presented.challenge)
            || desktop.control.attention != Some(presented.challenge.attention)
            || resolved_scope != presented.challenge.scope
            || input_serial <= presented.input_cut
        {
            return Err(Error::Stale);
        }
        resolved_scope.valid(desktop)?;
        if let ConfirmationSource::Assistive { sender, provider } = source {
            desktop.check_provider(
                sender,
                provider,
                ProviderRights::READ
                    .union(ProviderRights::ACTION)
                    .union(ProviderRights::CONFIRM),
            )?;
        }
        desktop.available_revision()?;
        desktop.control.input_serial = input_serial;
        desktop.control.invalidate();
        desktop.advance()?;
        Ok(Effect {
            scope: resolved_scope,
            nonce: presented.challenge.nonce,
        })
    }
    pub fn cancel(&mut self, desktop: &mut Desktop) -> Result<(), Error> {
        self.check(desktop)?;
        desktop.available_revision()?;
        desktop.control.invalidate();
        desktop.advance()
    }
}
impl Desktop {
    pub fn pending_challenge(&self) -> Option<Challenge> {
        self.control.pending
    }
    pub fn protected_semantic(
        &self,
        sender: Owner,
        lease: ProviderLease,
    ) -> Result<ProtectedSemanticView, Error> {
        self.check_provider(sender, lease, ProviderRights::READ)?;
        let presented = self.control.presented.ok_or(Error::Unsettled)?;
        Ok(ProtectedSemanticView {
            challenge: presented.challenge,
            frame: presented.frame,
            label: match presented.challenge.scope.kind {
                ProtectedKind::PickerConsent => "Confirm selected resource access",
                ProtectedKind::OwnerOverride => "Confirm deliberate owner authority",
                ProtectedKind::Revoke => "Confirm authority revocation",
                ProtectedKind::InstallLocalDevelopment => "Confirm local development installation",
                ProtectedKind::RunLocalDevelopment => "Confirm local development application run",
            },
            confirm_requires_adapter_witness: true,
        })
    }
}
