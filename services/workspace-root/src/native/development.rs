//! Actual local-owner development Install/Run. The immutable ingress is never
//! a startup actor, publisher signature or permission. Unknown work stays held.
use super::*;
use ev_workspace_root::{
    development::{self as model, Approval, Facts, Intent, Source as SoftwareSource},
    install_plan::Images,
};
use ev_workspace_shell::{Challenge, ConfirmationSource, PresentedWitness};
mod flow;
mod kernel;
mod storage;

struct Dialog {
    facts: Facts,
    intent: Intent,
    challenge: Challenge,
    witness: Option<PresentedWitness>,
    rearm: bool,
    drain_cut: u64,
    drained: bool,
}
#[derive(Clone, Copy)]
pub(super) struct Running {
    pub slot: usize,
    pub source: SoftwareSource,
    pub target: Actor,
}
type SoftwareView<'a> = (&'a [u8], SoftwareSource, Actor);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Initialize,
    Begin,
    Copy,
    Seal,
    Verify,
    Register,
    Allocate,
    CheckRegistry,
    CloseOld,
    AwaitOld,
    RetireFile,
    StopOld,
    DrainOld,
    ReapOld,
    CloseOldControl,
    CreateJob,
    CreateProcess,
    Delegate,
    Prepare,
    Enroll,
    Activate,
    Start,
    WaitReady,
    Complete,
    Fenced,
}
struct Pending {
    approval: Approval,
    step: Step,
    slot: Option<usize>,
    offset: usize,
    old: Actor,
    job: Option<u64>,
    held: Option<Actor>,
    delegated: usize,
    empty_after_stop: bool,
    activated: bool,
    registry: Option<ev_app_registry::Prepared>,
    storage_started: bool,
    last_call: Option<(u64, [u64; 4], rt::CapReply)>,
}
pub(super) struct Controller {
    dialog: Option<Dialog>,
    pending: Option<Pending>,
    images: Option<Images<kernel::Kernel>>,
    registered: Option<(SoftwareSource, usize)>,
    running: Option<Running>,
    status: &'static [u8],
    executing_cut: Option<u64>,
    executing_view: Option<ev_workspace_root::render::DevelopmentView>,
}
impl Controller {
    pub const fn new() -> Self {
        Self {
            dialog: None,
            pending: None,
            images: None,
            registered: None,
            running: None,
            status: b"Local development source available",
            executing_cut: None,
            executing_view: None,
        }
    }
    pub fn active(&self) -> bool {
        self.dialog.is_some() || self.pending.is_some() || self.executing_cut.is_some()
    }
    pub fn dialog(&self) -> bool {
        self.dialog.is_some()
    }
    pub fn armed(&self) -> bool {
        self.dialog
            .as_ref()
            .is_some_and(|d| d.witness.is_some() && !d.rearm)
    }
    pub fn nonce(&self) -> u64 {
        self.dialog.as_ref().map_or_else(
            || {
                self.pending.as_ref().map_or_else(
                    || self.executing_view.map_or(0, |v| v.nonce),
                    |p| p.approval.nonce(),
                )
            },
            |d| d.challenge.nonce,
        )
    }
    pub fn needs_barrier(&self) -> bool {
        self.dialog.as_ref().is_some_and(|d| d.rearm && d.drained)
    }
    pub fn cut(&self) -> Option<u64> {
        self.executing_cut.or_else(|| {
            self.pending
                .as_ref()
                .filter(|p| p.step != Step::Fenced)
                .map(|p| p.approval.cut())
        })
    }
    pub fn view(&self) -> Option<ev_workspace_root::render::DevelopmentView> {
        let (facts, intent, pending) = if let Some(d) = &self.dialog {
            (d.facts, d.intent, false)
        } else {
            let Some(p) = self.pending.as_ref() else {
                return self.executing_view.map(|mut view| {
                    view.status = self.status;
                    view
                });
            };
            (p.approval.facts(), p.approval.intent(), true)
        };
        Some(ev_workspace_root::render::DevelopmentView {
            source: facts.source,
            previous: facts.previous.identity,
            nonce: self.nonce(),
            intent,
            pending,
            status: self.status,
        })
    }
}
fn same_actor(a: Actor, b: Actor) -> bool {
    a.control == b.control && a.identity == b.identity && a.mapping_epoch == b.mapping_epoch
}
fn actual(actor: Actor) -> Result<bool, ()> {
    let who = rt::call4(s::PROCESS_IDENTITY, actor.control, 0, 0, 0);
    if who.status != 0
        || who.value != actor.identity.process
        || who.capability != actor.identity.thread
        || who.serial != 0
    {
        return Err(());
    }
    let r = rt::call4(s::OBSERVE, actor.control, 0, 0, 0);
    if r.status != 0 || r.capability != 0 || r.serial != 0 || r.value > 1 {
        return Err(());
    }
    Ok(r.value == 1)
}
fn source_bytes<'a>(catalogue: &'a Catalogue<'_>) -> Result<&'a [u8], ()> {
    let ingress = catalogue.external_ingress().ok_or(())?;
    let p = ingress.package;
    if ingress.provenance != v5::catalogue::IngressProvenance::LocalOwnerDevelopment {
        return Err(());
    }
    let len = usize::try_from(p.bytes).map_err(|_| ())?;
    if p.bank != v5::catalogue::PackageBank::Candidate
        || p.bytes > v5::resources::PACKAGE_MAX_BYTES
        || (p.offset as usize)
            .checked_add(len)
            .is_none_or(|end| end > p.bank.capacity_bytes() as usize)
    {
        return Err(());
    }
    let address = BASE + p.bank.first_page() as usize * 4096 + p.offset as usize;
    // SAFETY: actual Root's measured decoded catalogue and its retained RO bank;
    // full canonical bounds, no user pointer, remapping or writable reference.
    Ok(unsafe { core::slice::from_raw_parts(address as *const u8, len) })
}
impl Root<'_> {
    pub(super) fn development_semantic_available(&self, index: usize) -> bool {
        if self.development.active() {
            return false;
        }
        match self.development_software(index) {
            Ok(None) => true,
            Ok(Some((bytes, _, _))) => ev_zion::Package::parse(bytes).is_ok_and(|p| {
                p.app().contracts().any(|c| {
                    c.name == ev_workspace_client::semantic::INTERFACE
                        && c.major == ev_workspace_client::semantic::MAJOR
                })
            }),
            Err(()) => false,
        }
    }
    pub(super) fn development_software(
        &self,
        index: usize,
    ) -> Result<Option<SoftwareView<'_>>, ()> {
        if index != 2 {
            return Ok(None);
        }
        let Some(running) = self.development.running else {
            return Ok(None);
        };
        let current = self.actors[Child::EditorTwo.index()].ok_or(())?;
        if !same_actor(current, running.target) {
            return Err(());
        }
        let bytes = self
            .development
            .images
            .as_ref()
            .ok_or(())?
            .bytes(running.slot)
            .map_err(|_| ())?;
        let package = ev_zion::Package::parse(bytes).map_err(|_| ())?;
        if SoftwareSource::of(&package) != running.source {
            return Err(());
        }
        Ok(Some((bytes, running.source, running.target)))
    }
    pub(super) fn development_offer_click(&mut self, x: i32, serial: u32) -> bool {
        let offered = matches!(self.protected.body,Some(display::Body::Desktop(view))
            if view.mode==ev_workspace_root::render::Mode::Desktop&&view.development.is_some());
        if !offered || self.owner.pending.is_some() || self.grant.is_some() {
            return false;
        }
        let intent = if (0..140).contains(&x) {
            Intent::Install
        } else if (140..300).contains(&x) {
            Intent::Run
        } else {
            return false;
        };
        self.development_request(intent, serial);
        true
    }
    pub(super) fn development_offer(&self) -> Option<ev_workspace_root::render::DevelopmentView> {
        let p = self.catalogue.external_ingress()?.package;
        let old = self.actors[Child::EditorTwo.index()]?;
        Some(ev_workspace_root::render::DevelopmentView {
            source: SoftwareSource {
                app: p.app_id,
                package: p.digest,
                image: p.image,
                build: p.build,
                bytes: p.bytes,
            },
            previous: old.identity,
            nonce: 0,
            intent: Intent::Install,
            pending: false,
            status: b"Unsigned local development",
        })
    }
    fn development_enroll_exact(
        &mut self,
        held: Actor,
        descriptor: ev_workspace_root::app_data::descriptor::Descriptor,
        cut: u64,
    ) -> Result<(), ()> {
        let loaded = self.development_loaded()?;
        let available = self.app_data_available();
        let support =
            ev_workspace_root::requirements::PrivateDataContracts::new(&loaded, available);
        let checked = ev_workspace_root::requirements::private_file_app(
            source_bytes(&self.catalogue)?,
            &support,
        )
        .map_err(|_| ())?;
        self.private_data.enroll_held(
            Child::EditorTwo,
            held,
            descriptor,
            &checked,
            self.bootstrap.context().epoch,
            cut,
        )
    }
    fn development_bytes(&self) -> Result<&[u8], ()> {
        source_bytes(&self.catalogue)
    }
    fn development_loaded(
        &mut self,
    ) -> Result<ev_workspace_root::requirements::LoadedContracts, ()> {
        Ok(ev_workspace_root::requirements::LoadedContracts {
            semantic_tree: true,
            file: Some(self.workspace_file_support()?),
        })
    }
    fn development_facts(&mut self) -> Result<Facts, ()> {
        let loaded = self.development_loaded()?;
        let available = self.app_data_available();
        let support =
            ev_workspace_root::requirements::PrivateDataContracts::new(&loaded, available);
        let bytes = self.development_bytes()?;
        let checked =
            ev_workspace_root::requirements::private_file_app(bytes, &support).map_err(|_| ())?;
        model::private_profile(checked.package()).map_err(|_| ())?;
        let expected = self.catalogue.external_ingress().ok_or(())?.package;
        let p = checked.package();
        if p.id().bytes() != expected.digest
            || p.app().claimed_app.bytes() != expected.app_id
            || p.app().build_id != expected.build
            || p.executable().digest != expected.image
        {
            return Err(());
        }
        let old = self.actors[Child::EditorTwo.index()].ok_or(())?;
        let _ = actual(old)?;
        Facts::capture(&checked, old, self.protected.identity).ok_or(())
    }
    pub(super) fn development_request(&mut self, intent: Intent, serial: u32) {
        if self.development.active()
            || self.shutdown.active()
            || self.owner.pending.is_some()
            || self.grant.is_some()
            || !self.app_data_can_stop()
        {
            return;
        }
        let Ok(facts) = self.development_facts() else {
            self.status = b"Local development source or actual services are unavailable";
            self.owner.dirty = true;
            return;
        };
        if ev_workspace_root::shutdown::unfinished_documents(&self.states) {
            self.status = b"Save or recover unfinished work before replacing Editor2";
            self.owner.dirty = true;
            return;
        }
        self.cancel_owner();
        self.semantic_revoke(true);
        let scope = facts.scope(intent);
        let policy = self.policy.as_mut().unwrap();
        let Ok(attention) = policy
            .trusted
            .attest_attention(&mut policy.desktop, self.input.serial(serial))
        else {
            return;
        };
        let Ok(challenge) = policy
            .trusted
            .challenge(&mut policy.desktop, attention, scope)
        else {
            return;
        };
        self.development.status = match intent {
            Intent::Install => {
                b"Unsigned owner development: install exact source and NEW private data"
            }
            Intent::Run => {
                b"Run exact installed source; close only clean Editor2; private data retained"
            }
        };
        self.development.dialog = Some(Dialog {
            facts,
            intent,
            challenge,
            witness: None,
            rearm: true,
            drain_cut: deadline(v5::resources::FILE_TRANSACTION_TICKS),
            drained: false,
        });
        self.owner.dirty = true;
    }
    pub(super) fn development_cancel(&mut self) {
        if self.development.dialog.take().is_some() {
            let policy = self.policy.as_mut().unwrap();
            let _ = policy.trusted.cancel(&mut policy.desktop);
            self.input.cancel();
            self.owner.dirty = true;
        }
    }
    pub(super) fn development_presented(&mut self, frame: u64) {
        if !self.development.needs_barrier() {
            return;
        }
        let Some((facts, intent)) = self
            .development
            .dialog
            .as_ref()
            .map(|d| (d.facts, d.intent))
        else {
            return;
        };
        if self.development_facts().ok() != Some(facts) {
            self.development_cancel();
            return;
        }
        self.owner.input_nonce = match self
            .owner
            .input_nonce
            .checked_add(1)
            .filter(|v| *v != u32::MAX)
        {
            Some(n) => n,
            None => {
                self.development_cancel();
                return;
            }
        };
        let request = ev_input::SessionBarrierRequest::new(self.owner.input_nonce).unwrap();
        let response = rt::rpc::call(
            self.channel(Channel::InputBarrier),
            request.encode(),
            deadline(v5::resources::RPC_TICKS),
        );
        let Some(barrier) = response
            .ok()
            .and_then(|b| ev_input::SessionBarrierReply::decode(b).ok())
        else {
            self.development_cancel();
            return;
        };
        self.input.arm(barrier);
        let scope = facts.scope(intent);
        let policy = self.policy.as_mut().unwrap();
        let d = self.development.dialog.as_mut().unwrap();
        match policy.trusted.attest_presented(
            &mut policy.desktop,
            d.challenge,
            scope,
            frame,
            self.input.serial(barrier.sequence),
        ) {
            Ok(witness) => {
                d.witness = Some(witness);
                d.rearm = false;
            }
            Err(_) => self.development_cancel(),
        }
    }
    pub(super) fn development_confirm(&mut self, serial: u32) {
        let Some(mut dialog) = self.development.dialog.take() else {
            return;
        };
        if !dialog.drained || dialog.witness.is_none() {
            self.development.dialog = Some(dialog);
            return;
        }
        if self.development_facts().ok() != Some(dialog.facts)
            || self.grant.is_some()
            || !self.app_data_can_stop()
            || ev_workspace_root::shutdown::unfinished_documents(&self.states)
        {
            self.development.dialog = Some(dialog);
            self.development_cancel();
            self.status = b"Installation target or pending work changed; request a fresh decision";
            self.owner.dirty = true;
            return;
        }
        let policy = self.policy.as_mut().unwrap();
        let scope = dialog.facts.scope(dialog.intent);
        let effect = policy.trusted.attest_confirmation(
            &mut policy.desktop,
            dialog.witness.take().unwrap(),
            scope,
            self.input.serial(serial),
            ConfirmationSource::Physical,
        );
        let Ok(effect) = effect else {
            dialog.rearm = true;
            self.development.dialog = Some(dialog);
            self.owner.dirty = true;
            return;
        };
        let time = now();
        let Some(cut) = time
            .checked_add(v5::resources::FILE_TRANSACTION_TICKS)
            .filter(|v| *v != u64::MAX)
        else {
            return;
        };
        let Ok(approval) = model::approve(dialog.facts, dialog.intent, effect, time, cut) else {
            return;
        };
        let old = self.actor(Child::EditorTwo);
        let step = if dialog.intent == Intent::Run {
            Step::CheckRegistry
        } else {
            Step::Initialize
        };
        self.development.pending = Some(Pending {
            approval,
            step,
            slot: None,
            offset: 0,
            old,
            job: None,
            held: None,
            delegated: 0,
            empty_after_stop: false,
            activated: false,
            registry: None,
            storage_started: false,
            last_call: None,
        });
        self.owner.dirty = true;
    }
    pub(super) fn development_events_empty(&mut self) {
        if let Some(p) = self.development.pending.as_mut()
            && p.step == Step::DrainOld
        {
            p.empty_after_stop = true;
        }
    }
    pub(super) fn development_event(&mut self, child: Child, bytes: [u8; 8]) -> bool {
        if !self.development.active() {
            return false;
        }
        if ev_userspace_contract::root_v5::assistive::Intent::decode(bytes).is_ok() {
            return true;
        }
        if let Ok(event) = Event::decode(bytes) {
            match event {
                Event::State(state) => {
                    if let Some(slot) = child_slot(child)
                        && slot.index() < 4
                    {
                        self.states[slot.index()] = Some(state);
                    }
                }
                Event::Ready(_) => return false,
                Event::CloseNeedsDiscard if child == Child::EditorTwo => {
                    if let Some(p) = self.development.pending.as_mut() {
                        p.step = Step::Fenced;
                    }
                }
                _ => (),
            }
            return true;
        }
        false // Actual A1/IS drain frames still reach their existing receivers.
    }
}
