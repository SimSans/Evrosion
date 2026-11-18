//! Sequential same-app fixtures. Artifact identity and replay-floor name stay
//! independent of transport filenames, metadata author dates and local recovery.
use super::*;
use ev_release_trust::{metadata::Target, verifier::Verified};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixturePhase {
    B,
    C,
}
impl FixturePhase {
    pub const fn artifact_version(self) -> u64 {
        match self {
            Self::B => 2,
            Self::C => 3,
        }
    }
    pub const fn initial_metadata_version(self) -> u64 {
        match self {
            Self::B => 1,
            Self::C => 2,
        }
    }
    fn index(self) -> usize {
        match self {
            Self::B => 0,
            Self::C => 1,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::B => "b",
            Self::C => "c",
        }
    }
    fn variant(self) -> crate::native_package::Downloaded {
        match self {
            Self::B => crate::native_package::Downloaded::B,
            Self::C => crate::native_package::Downloaded::C,
        }
    }
}
/// Stable independently expected replay-floor name. It never contains a key,
/// filename, release version, candidate digest or attacker-supplied App claim.
pub fn logical_target_name() -> [u8; 32] {
    mod anchor {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/m6/fixtures/development-target.rs"
        ));
    }
    let b = crate::development_release::binding();
    let mut h = Sha256::new();
    h.update(b"evrosion.DEVELOPMENT.logical-app-target.v1\0");
    h.update(crate::native_package::HELLO_APP_ID);
    h.update(b.namespace);
    h.update(b.channel);
    h.update(b.platform);
    let name = h.finalize().into();
    assert_eq!(
        name,
        anchor::HELLO_TARGET_NAME,
        "independent development target anchor drift"
    );
    name
}
pub struct PhaseFixture {
    pub phase: FixturePhase,
    pub directory: PathBuf,
    assets: [(&'static str, Vec<u8>); 5],
}
impl PhaseFixture {
    pub fn asset(&self, path: &str) -> Option<&[u8]> {
        self.assets
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, b)| b.as_slice())
    }
}
struct Candidate<'a> {
    source: [u8; 32],
    bytes: &'a [u8],
    package: [u8; 32],
    build: [u8; 32],
    descriptor: [u8; 32],
    image: [u8; 32],
}
fn target_spec(phase: FixturePhase, c: &Candidate<'_>) -> TargetSpec {
    let mut h = Sha256::new();
    h.update(b"evrosion.DEVELOPMENT.same-app-candidate.v1\0");
    h.update(logical_target_name());
    h.update(phase.artifact_version().to_le_bytes());
    h.update(c.source);
    h.update(c.package);
    h.update(c.build);
    h.update(c.descriptor);
    let candidate: [u8; 32] = h.finalize().into();
    let mut generation = Sha256::new();
    generation.update(b"evrosion.DEVELOPMENT.candidate-generation.v1\0");
    generation.update(candidate);
    let mut release = Sha256::new();
    release.update(b"evrosion.DEVELOPMENT.candidate-release.v1\0");
    release.update(candidate);
    let mut provenance = Sha256::new();
    provenance.update(b"evrosion.DEVELOPMENT.same-app-provenance.v1\0");
    provenance.update(c.source);
    provenance.update(c.image);
    provenance.update(c.package);
    TargetSpec {
        name: logical_target_name(),
        version: phase.artifact_version(),
        length: c.bytes.len() as u64,
        sha256: hash(c.bytes),
        generation: generation.finalize().into(),
        release: release.finalize().into(),
        source_revision: c.source,
        build: c.build,
        provenance: provenance.finalize().into(),
        contract: c.descriptor,
    }
}
/// The first B/C fixtures use metadata1/2. Explicit later reauthoring requires a
/// newly signed, monotonic metadata version; artifact floors remain2/3. No date
/// refresh can lower/reset a consumer's retained target or metadata floors.
pub fn sign_phase(
    root: &Path,
    bundle: &Bundle,
    authority: &Authority,
    phase: FixturePhase,
    author: Author,
    destination: &Path,
) -> Result<PhaseFixture, String> {
    if author.version < phase.initial_metadata_version() {
        return Err("phase metadata version below declared initial sequence".into());
    }
    let Validated {
        source,
        out: _,
        packages,
    } = validated(root, bundle, authority)?;
    let row = &bundle.downloads[phase.index()];
    let candidate = Candidate {
        source,
        bytes: &packages[phase.index()],
        package: row.package_id,
        build: row.build,
        descriptor: row.component.descriptor,
        image: row.component.image_sha256,
    };
    let spec = target_spec(phase, &candidate);
    let signed = authority.sign_candidate(author, spec)?;
    // Explicit fresh caller-owned output keeps the original production source,
    // raw ELF/Zion and comparison proof directories byte-for-byte untouched.
    let parent = fs::canonicalize(destination.parent().ok_or("phase output parent")?)
        .map_err(|e| e.to_string())?;
    let name = destination.file_name().ok_or("phase output name")?;
    let directory = parent.join(name);
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    let assets = [
        ("/release/root.bin", authority.root().to_vec()),
        ("/release/targets.bin", signed.targets),
        ("/release/snapshot.bin", signed.snapshot),
        ("/release/timestamp.bin", signed.timestamp),
        ("/artifacts/hello.zion", candidate.bytes.to_vec()),
    ];
    let mut routes = Vec::new();
    for (path, b) in &assets {
        let name = path.rsplit('/').next().unwrap();
        write(&directory.join(name), b)?;
        routes.push(serde_json::json!({"route":path,"file":name,"bytes":b.len(),"sha256":format!("{:x}",Sha256::digest(b))}));
    }
    write(&directory.join("phase.json"),&serde_json::to_vec_pretty(&serde_json::json!({"schema":1,"scope":"DEVELOPMENT single-candidate same-app remote update fixture; no local KnownGood authorization","phase":phase.label(),"app":crate::native_package::HELLO_APP_ID,"logical_target_name":spec.name,"artifact_version":spec.version,"metadata_version":author.version,"root_version":1,"generation":spec.generation,"release":spec.release,"source_sha256":bundle.source_sha256,"package":row.package_id,"build":row.build,"descriptor":row.component.descriptor,"author_not_before":author.not_before,"author_expires":author.expires,"author_labels_are_not_acceptance_time":true,"routes":routes})).map_err(|e|e.to_string())?)?;
    Ok(PhaseFixture {
        phase,
        directory,
        assets,
    })
}
/// Model of the consumer's independently expected same-app selection boundary,
/// after the common verifier. A matching AppId under a new target name cannot
/// reset its floor. This returns metadata only, not local recovery authority.
pub fn select_phase<'a>(
    phase: FixturePhase,
    verified: &Verified<'a>,
    bytes: &[u8],
) -> Result<Target<'a>, String> {
    if verified.targets().len() != 1 {
        return Err("same-app candidate must have exactly one target".into());
    }
    let target = verified
        .verify_artifact(logical_target_name(), bytes)
        .map_err(|e| format!("expected logical target/artifact: {e:?}"))?;
    let spec = target.spec();
    if spec.version != phase.artifact_version() {
        return Err("unexpected same-app artifact version".into());
    }
    let p = ev_zion::Package::parse(bytes).map_err(|e| format!("candidate Zion: {e:?}"))?;
    if p.app().claimed_app.bytes() != crate::native_package::HELLO_APP_ID {
        return Err("same-app candidate AppId differs".into());
    }
    let actual = crate::native_package::downloaded_hello(
        p.executable().bytes,
        spec.source_revision,
        phase.variant(),
    )?;
    if actual.bytes != bytes || actual.build != spec.build || actual.descriptor != spec.contract {
        return Err("candidate source/build/contract differs from authenticated target".into());
    }
    Ok(target)
}
#[cfg(test)]
mod tests;
