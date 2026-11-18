//! Explicit Host fixture production, separate from every Kernel image bank.
//! Creation/signing never installs an application or establishes UTC trust.
pub use crate::development_release::{Author, Authority, SignedRelease, provision};
pub use crate::supervisor::download_graph::{
    Bundle, Component, Download, produce, produce_document,
};
use ev_release_trust::metadata::TargetSpec;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub struct Fixture {
    assets: [(&'static str, Vec<u8>); 6],
    pub directory: PathBuf,
}
/// Explicit bounded DEV phase server for the owned VM's existing scoped
/// destination. It owns public serving bytes only; signing keys never enter it.
pub struct Server {
    inner: crate::network_fixture::Fixture,
}
impl Server {
    /// Start Hello/time service with release routes absent. The owner may
    /// freshly author/publish B after actual long virgin initialization.
    pub fn pending() -> Result<Self, String> {
        Ok(Self {
            inner: crate::network_fixture::Fixture::acquisition_pending()?,
        })
    }
    pub fn start(phase: phase::PhaseFixture) -> Result<Self, String> {
        Ok(Self {
            inner: crate::network_fixture::Fixture::acquisition(phase)?,
        })
    }
    /// Explicit pending->B or B->C public publication. Existing accepted replies
    /// retain their own exact selected bytes; a route switch creates no trust.
    pub fn replace_phase(&self, phase: phase::PhaseFixture) -> Result<(), String> {
        self.inner.replace_phase(phase)
    }
    pub(crate) fn served(&self) -> u64 {
        self.inner.served()
    }
    pub fn snapshot(&self) -> Result<serde_json::Value, String> {
        serde_json::to_value(self.inner.snapshot()?).map_err(|e| e.to_string())
    }
    pub(crate) fn actual_snapshot(&self) -> Result<crate::network_fixture::Snapshot, String> {
        self.inner.snapshot()
    }
    pub fn provenance(&self) -> Result<serde_json::Value, String> {
        self.inner.acquisition_receipt()
    }
}
impl Fixture {
    /// Exact immutable route lookup for the owned Host fixture server. No
    /// signing key is retained in this serving object and paths confer no trust.
    pub fn asset(&self, path: &str) -> Option<&[u8]> {
        self.assets
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, bytes)| bytes.as_slice())
    }
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn read(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.len() == 0 || m.len() > max {
        return Err("fixture input must be bounded regular bytes".into());
    }
    fs::read(path).map_err(|e| e.to_string())
}
/// Parse a retained production record. Signing still revalidates every actual
/// raw/stripped ELF, package, source field and independent anchor below.
pub fn load_bundle(directory: &Path) -> Result<Bundle, String> {
    serde_json::from_slice(&read(&directory.join("download-manifest.json"), 65536)?)
        .map_err(|e| e.to_string())
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())
}
/// Two-artifact comparison set only, not a sequential same-app update.
/// Sign only the exact separately built B/C packages, then return public
/// immutable serving bytes. The actual client must independently pin Root,
/// qualify time and atomically commit replay/floor state before accepting them.
pub fn sign_fixture(root: &Path, bundle: &Bundle, author: Author) -> Result<Fixture, String> {
    let authority = Authority::load(root)?;
    sign_with_authority(root, bundle, &authority, author)
}
/// A separately frozen build copy may borrow this explicit private Host signer
/// without copying its keys into that copy or the served fixture. Its public
/// source anchor must exactly equal the independently provisioned signer Root.
pub fn sign_with_authority(
    root: &Path,
    bundle: &Bundle,
    authority: &Authority,
    author: Author,
) -> Result<Fixture, String> {
    let Validated {
        source,
        out,
        mut packages,
    } = validated(root, bundle, authority)?;
    let mut cohort = Sha256::new();
    cohort.update(b"evrosion.DEVELOPMENT.download-cohort.v1\0");
    cohort.update(source);
    for r in &bundle.downloads {
        cohort.update(r.package_id);
    }
    let generation: [u8; 32] = cohort.finalize().into();
    let mut release = Sha256::new();
    release.update(b"evrosion.DEVELOPMENT.download-release.v1\0");
    release.update(generation);
    release.update(author.version.to_le_bytes());
    let release = release.finalize().into();
    let specs = core::array::from_fn(|index| {
        let row = &bundle.downloads[index];
        let label = if index == 0 {
            "hello-b.zion"
        } else {
            "hello-c.zion"
        };
        let mut provenance = Sha256::new();
        provenance.update(b"evrosion.DEVELOPMENT.download-provenance.v1\0");
        provenance.update(source);
        provenance.update(row.component.feature.as_bytes());
        provenance.update(row.component.image_sha256);
        provenance.update(row.package_sha256);
        TargetSpec {
            name: hash(label.as_bytes()),
            version: author.version,
            length: packages[index].len() as u64,
            sha256: row.package_sha256,
            generation,
            release,
            source_revision: source,
            build: row.build,
            provenance: provenance.finalize().into(),
            contract: row.component.descriptor,
        }
    });
    let signed = authority.sign(author, &specs)?;
    signed.check_signatures(authority.root())?;
    let directory = out.join(format!("metadata-v{}", author.version));
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    let assets = [
        ("/release/root.bin", authority.root().to_vec()),
        ("/release/targets.bin", signed.targets),
        ("/release/snapshot.bin", signed.snapshot),
        ("/release/timestamp.bin", signed.timestamp),
        ("/artifacts/hello-b.zion", packages.remove(0)),
        ("/artifacts/hello-c.zion", packages.remove(0)),
    ];
    let mut rows = Vec::new();
    for (path, bytes) in &assets {
        let name = path.rsplit('/').next().unwrap();
        write(&directory.join(name), bytes)?;
        rows.push(serde_json::json!({"route":path,"file":name,"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes))}));
    }
    write(&directory.join("fixture.json"),&serde_json::to_vec_pretty(&serde_json::json!({"schema":1,"authority":"DEVELOPMENT ONLY, not Official","independent_root":crate::development_release::ROOT_FILE,"source_sha256":bundle.source_sha256,"author_version":author.version,"author_not_before":author.not_before,"author_expires":author.expires,"author_timestamps_are_not_acceptance_time":true,"consumer_obligations":["independently pinned Root","actual qualified time","atomic durable replay/floor","exact artifact admission and ownership"],"routes":rows})).map_err(|e|e.to_string())?)?;
    Ok(Fixture { assets, directory })
}

struct Validated<'a> {
    source: [u8; 32],
    out: &'a Path,
    packages: Vec<Vec<u8>>,
}
fn validated<'a>(
    root: &Path,
    bundle: &'a Bundle,
    authority: &Authority,
) -> Result<Validated<'a>, String> {
    if read(&root.join(crate::development_release::ROOT_FILE), 8192)? != authority.root() {
        return Err("artifact source anchor differs from independent signing authority".into());
    }
    validated_content(root, bundle)
}
pub(crate) fn validate_bundle(root: &Path, bundle: &Bundle) -> Result<(), String> {
    validated_content(root, bundle).map(|_| ())
}
fn validated_content<'a>(root: &Path, bundle: &'a Bundle) -> Result<Validated<'a>, String> {
    if bundle.compiled_into_kernel || bundle.schema != 1 {
        return Err("download fixture profile".into());
    }
    let mut source = [0; 32];
    if bundle.source_sha256.len() != 64
        || !bundle
            .source_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("download source must be canonical64hex".into());
    }
    for (i, v) in source.iter_mut().enumerate() {
        *v = u8::from_str_radix(&bundle.source_sha256[2 * i..2 * i + 2], 16)
            .map_err(|e| e.to_string())?;
    }
    let base = fs::canonicalize(root)
        .map_err(|e| e.to_string())?
        .join("build/m6/downloads");
    let out = bundle.downloads[0]
        .package
        .parent()
        .ok_or("missing download directory")?;
    let rel = out
        .strip_prefix(&base)
        .map_err(|_| "download package output escapes owned fixture directory")?;
    if rel.components().count() != 1
        || !matches!(
            rel.components().next(),
            Some(std::path::Component::Normal(_))
        )
        || !fs::symlink_metadata(out)
            .map_err(|e| e.to_string())?
            .is_dir()
    {
        return Err("download fixture directory shape".into());
    }
    let mut packages = Vec::new();
    for (i, row) in bundle.references.iter().enumerate() {
        if row.image.parent() != Some(out)
            || row.unstripped.parent() != Some(out)
            || row.feature
                != if i == 0 {
                    if bundle.document {
                        "native-a,document-workflow"
                    } else {
                        "native-a,native-session"
                    }
                } else {
                    if bundle.document {
                        "native-b,document-workflow"
                    } else {
                        "native-b,native-session"
                    }
                }
        {
            return Err("precompiled comparison reference shape changed".into());
        }
        crate::supervisor::download_graph::check_component(row)?;
    }
    for (index, row) in bundle.downloads.iter().enumerate() {
        if row.package.parent() != Some(out) || row.component.image.parent() != Some(out) {
            return Err("mixed download fixture directories".into());
        }
        if row.component.unstripped.parent() != Some(out)
            || row.component.feature
                != if index == 0 {
                    if bundle.document {
                        "downloaded-b,document-workflow"
                    } else {
                        "downloaded-b"
                    }
                } else {
                    if bundle.document {
                        "downloaded-c,document-workflow"
                    } else {
                        "downloaded-c"
                    }
                }
        {
            return Err("downloaded component feature/retained raw shape changed".into());
        }
        let image = crate::supervisor::download_graph::check_component(&row.component)?;
        let builder = if bundle.document {
            crate::native_package::downloaded_document_hello
        } else {
            crate::native_package::downloaded_hello
        };
        let actual = builder(
            &image,
            source,
            if index == 0 {
                crate::native_package::Downloaded::B
            } else {
                crate::native_package::Downloaded::C
            },
        )?;
        let package = read(&row.package, ev_kernel::dynamic_image::MAX_BYTES as u64)?;
        if package != actual.bytes
            || hash(&image) != row.component.image_sha256
            || actual.descriptor != row.component.descriptor
            || actual.package != row.package_id
            || actual.build != row.build
            || actual.app != row.app
            || hash(&package) != row.package_sha256
        {
            return Err("download package/component/provenance readback mismatch".into());
        }
        if bundle
            .references
            .iter()
            .any(|r| r.image_sha256 == row.component.image_sha256)
        {
            return Err("download aliases a precompiled reference".into());
        }
        packages.push(package);
    }
    if bundle.downloads[0].component.image_sha256 == bundle.downloads[1].component.image_sha256 {
        return Err("download B/C image identity aliases".into());
    }
    Ok(Validated {
        source,
        out,
        packages,
    })
}
mod phase;
pub use phase::{FixturePhase, PhaseFixture, logical_target_name, select_phase, sign_phase};
