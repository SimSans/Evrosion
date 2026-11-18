//! Authenticate bounded metadata before consuming permanent image resources.
//! Preparation is not a remote decision, checkpoint, executable or lifecycle.
use super::*;
use ev_content_store::Backend;
use ev_release_trust::{
    metadata as md,
    signature::Envelope,
    verifier::{self, TrustedRoot},
};
use ev_time_contract::freshness::Time;

#[must_use = "preparation authorizes only exact immutable resource inputs; final candidate authorization remains mandatory"]
pub struct Preparation {
    target: md::TargetSpec,
    metadata: [md::Identity; 3],
    binding: AuthorizationBinding,
}
impl Preparation {
    pub const fn target(&self) -> md::TargetSpec {
        self.target
    }
    /// Targets/Snapshot/Timestamp raw envelope identities, in that order.
    pub fn metadata(&self, index: usize) -> Option<md::Identity> {
        self.metadata.get(index).copied()
    }
    pub const fn prior(&self) -> AuthorizationBinding {
        self.binding
    }
}
impl<B: Backend> Store<B> {
    /// No Arena write, image allocation, replay mutation or artifact claim.
    /// The private actual runtime supplies the same Store-bound qualified clock
    /// used by full authorization; TEST clocks never qualify a runtime provider.
    pub fn prepare_metadata<C: QualifiedClock>(
        &self,
        current_root: &[u8],
        bundle: verifier::Bundle<'_>,
        clock: &mut C,
    ) -> Result<Preparation, Fault> {
        if self.has_unresolved_io() {
            return Err(Fault::Phase);
        }
        let binding = self.authorization_binding().ok_or(Fault::Unprovisioned)?;
        let current = self.state.as_ref().ok_or(Fault::Unprovisioned)?;
        let object = current.current_root_object().ok_or(Fault::Root)?;
        if current_root.len() > ROOT_BUFFER
            || current_root.len() as u64 != object.length()
            || digest(current_root) != object.sha256()
        {
            return Err(Fault::Root);
        }
        let root =
            TrustedRoot::provisioned(current_root, super::binding()).map_err(|_| Fault::Root)?;
        if root.identity() != current.replay.root() {
            return Err(Fault::Root);
        }
        if bundle.targets.len() > TARGET_BUFFER
            || bundle.snapshot.len() > LINK_BUFFER
            || bundle.timestamp.len() > LINK_BUFFER
        {
            return Err(Fault::Metadata);
        }
        let (first, first_at) = clock.fresh().map_err(|_| Fault::Time)?;
        let verified = verifier::verify_bundle(
            &root,
            &current.replay,
            verifier::Bundle {
                targets: bundle.targets,
                snapshot: bundle.snapshot,
                timestamp: bundle.timestamp,
            },
            Time::Qualified(first),
            first_at,
            verifier::Policy::new(8, ev_content_store::MAX_OBJECT_BYTES)
                .map_err(|_| Fault::Metadata)?,
        )
        .map_err(|_| Fault::Metadata)?;
        if verified.targets().len() != 1 {
            return Err(Fault::Candidate);
        }
        let target = verified.targets().next().ok_or(Fault::Candidate)?.spec();
        if target.name != logical_target_name() || !matches!(target.version, 2 | 3) {
            return Err(Fault::Candidate);
        }
        let te = Envelope::parse(bundle.targets).map_err(|_| Fault::Metadata)?;
        let se = Envelope::parse(bundle.snapshot).map_err(|_| Fault::Metadata)?;
        let tse = Envelope::parse(bundle.timestamp).map_err(|_| Fault::Metadata)?;
        let metadata = [
            md::Targets::parse(&te)
                .map_err(|_| Fault::Metadata)?
                .identity(),
            md::Linked::parse(&se)
                .map_err(|_| Fault::Metadata)?
                .identity(),
            md::Linked::parse(&tse)
                .map_err(|_| Fault::Metadata)?
                .identity(),
        ];
        decision::post_crypto_floor(&root, bundle, verified.proposed(), first_at, clock)?;
        if self.authorization_binding() != Some(binding) {
            return Err(Fault::Phase);
        }
        Ok(Preparation {
            target,
            metadata,
            binding,
        })
    }
}
