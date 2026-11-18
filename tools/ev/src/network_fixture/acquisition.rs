//! Immutable public DEV phase assets. The serving owner never contains keys;
//! source production/signing and consumer authorization remain separate.
use super::*;
use crate::download_fixture::{FixturePhase, PhaseFixture};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
pub(super) const ARTIFACT_PATH: &str = "/artifacts/hello.zion";
const PATHS: [&str; 4] = [
    "/release/targets.bin",
    "/release/snapshot.bin",
    "/release/timestamp.bin",
    ARTIFACT_PATH,
];
pub(super) struct Routes {
    current: Option<PhaseFixture>,
    history: Vec<Value>,
}
impl Routes {
    pub(super) fn pending() -> Self {
        Self {
            current: None,
            history: Vec::new(),
        }
    }
    pub(super) fn new(phase: PhaseFixture) -> Result<Self> {
        if phase.phase != FixturePhase::B {
            return Err("acquisition fixture must start with explicit DEV B phase".into());
        }
        let receipt = checked(&phase)?;
        Ok(Self {
            current: Some(phase),
            history: vec![receipt],
        })
    }
    pub(super) fn replace(&mut self, phase: PhaseFixture) -> Result<()> {
        match self.current.as_ref() {
            None if phase.phase == FixturePhase::B && self.history.is_empty() => (),
            Some(old)
                if old.phase == FixturePhase::B
                    && phase.phase == FixturePhase::C
                    && self.history.len() == 1 => {}
            _ => return Err("acquisition fixture publication is not pending->B->C".into()),
        }
        let receipt = checked(&phase)?;
        if self
            .current
            .as_ref()
            .is_some_and(|old| old.asset("/release/root.bin") != phase.asset("/release/root.bin"))
        {
            return Err("acquisition phase changed the independent DEV Root".into());
        }
        self.current = Some(phase);
        self.history.push(receipt);
        Ok(())
    }
    pub(super) fn asset(&self, path: &str) -> Result<Option<Vec<u8>>> {
        if !PATHS.contains(&path) {
            return Ok(None);
        }
        let Some(current) = self.current.as_ref() else {
            return Ok(None);
        };
        current
            .asset(path)
            .map(|b| b.to_vec())
            .map(Some)
            .ok_or_else(|| "acquisition public route disappeared".into())
    }
    pub(super) fn receipt(&self) -> Value {
        json!({"phase":match self.current.as_ref().map(|p|p.phase){None=>"pending",Some(FixturePhase::B)=>"b",Some(FixturePhase::C)=>"c"},"history":self.history,"authority":"DEVELOPMENT only, not Official","consumer_authorization_claim":false})
    }
}
fn checked(phase: &PhaseFixture) -> Result<Value> {
    use ev_root_supervisor::native_acquisition::{LINK_BUFFER, TARGET_BUFFER};
    // Public consistency only. Rechecking the mutable phase label must not
    // manufacture consumer time/replay authority or a Verified token.
    let signed = crate::development_release::SignedRelease {
        targets: phase
            .asset("/release/targets.bin")
            .ok_or("missing targets")?
            .to_vec(),
        snapshot: phase
            .asset("/release/snapshot.bin")
            .ok_or("missing snapshot")?
            .to_vec(),
        timestamp: phase
            .asset("/release/timestamp.bin")
            .ok_or("missing timestamp")?
            .to_vec(),
    };
    signed.check_signatures(
        phase
            .asset("/release/root.bin")
            .ok_or("missing public DEV Root")?,
    )?;
    let envelope = ev_release_trust::signature::Envelope::parse(&signed.targets)
        .map_err(|_| "public phase targets framing")?;
    let targets = ev_release_trust::metadata::Targets::parse(&envelope)
        .map_err(|_| "public phase targets")?;
    if targets.count() != 1 || targets.common().version < phase.phase.initial_metadata_version() {
        return Err("public phase target count/version".into());
    }
    let target = targets.iter().next().unwrap();
    if target.spec().name != crate::download_fixture::logical_target_name()
        || target.spec().version != phase.phase.artifact_version()
    {
        return Err("public phase target label differs".into());
    }
    target
        .verify_bytes(
            phase
                .asset(ARTIFACT_PATH)
                .ok_or("missing public artifact")?,
            262144,
        )
        .map_err(|_| "public phase raw artifact identity")?;
    let mut routes = Vec::new();
    for path in PATHS {
        let bytes = phase
            .asset(path)
            .ok_or("acquisition fixture missing fixed route")?;
        let maximum = match path {
            ARTIFACT_PATH => 262144,
            "/release/targets.bin" => TARGET_BUFFER,
            _ => LINK_BUFFER,
        };
        if bytes.is_empty() || bytes.len() > maximum {
            return Err("acquisition fixture route exceeds exact consumer bound".into());
        }
        routes.push(
            json!({"path":path,"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes))}),
        );
    }
    Ok(
        json!({"phase":if phase.phase==FixturePhase::B {"b"}else{"c"},"directory":phase.directory,"routes":routes,"public_assets_only":true,"author_time_is_untrusted_to_consumer":true}),
    )
}
