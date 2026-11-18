//! Explicit, independently provisioned DEVELOPMENT signing authority. Host
//! author dates are metadata inputs; no API here creates qualified UTC time,
//! a durable replay checkpoint, Official status or executable permission.
use ed25519_dalek::{Signer, SigningKey};
use ev_release_trust::{
    metadata::{self as md, Binding, Common, Identity, RolePolicy, TargetSpec},
    signature::{self, Envelope, PublicKey, Role},
    verifier::TrustedRoot,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

const NAMES: [&str; 5] = [
    "root-a.seed",
    "root-b.seed",
    "targets.seed",
    "snapshot.seed",
    "timestamp.seed",
];
const ROLES: [&str; 5] = ["root", "root", "targets", "snapshot", "timestamp"];
const LIFETIMES: [u32; 4] = [31_536_000, 86_400, 3_600, 600];
pub const ROOT_FILE: &str = "tools/m6/fixtures/development-root.bin";
pub const PUBLIC_FILE: &str = "tools/m6/fixtures/development-authority.json";
fn digest(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
pub fn binding() -> Binding {
    Binding {
        namespace: digest(b"evrosion.DEVELOPMENT.download-authority.v1\0"),
        channel: digest(b"development\0"),
        platform: digest(b"evrosion.x86_64.vm.root-v4.app-v1\0"),
    }
}

/// Author-supplied UTC labels/version, not observations of acceptable time.
#[derive(Clone, Copy, Debug)]
pub struct Author {
    pub version: u64,
    pub not_before: u64,
    pub expires: u64,
}
impl Author {
    fn common(self) -> Common {
        Common {
            binding: binding(),
            version: self.version,
            root_version: 1,
            not_before: self.not_before,
            expires: self.expires,
        }
    }
}
/// Private key-bearing owner intentionally has no Clone, Debug or serialization.
pub struct Authority {
    keys: [SigningKey; 5],
    root: Vec<u8>,
}
pub struct SignedRelease {
    pub targets: Vec<u8>,
    pub snapshot: Vec<u8>,
    pub timestamp: Vec<u8>,
}
fn public(k: &SigningKey) -> Result<PublicKey, String> {
    PublicKey::parse(k.verifying_key().to_bytes())
        .map_err(|e| format!("development public key: {e:?}"))
}
fn signed(role: Role, payload: &[u8], keys: &[&SigningKey]) -> Result<Vec<u8>, String> {
    let mut out = signature::header(role, payload.len(), keys.len())
        .map_err(|e| format!("signature header: {e:?}"))?
        .to_vec();
    out.extend_from_slice(payload);
    let mut sigs = keys
        .iter()
        .map(|key| Ok((public(key)?.id(), key.sign(&out).to_bytes())))
        .collect::<Result<Vec<_>, String>>()?;
    sigs.sort_by_key(|r| r.0);
    for (id, sig) in sigs {
        out.extend_from_slice(&id);
        out.extend_from_slice(&sig);
    }
    Ok(out)
}
fn root_bytes(keys: &[SigningKey; 5], author: Author) -> Result<Vec<u8>, String> {
    if author.version != 1 {
        return Err("initial development Root version must be1".into());
    }
    let mut publics = keys.iter().map(public).collect::<Result<Vec<_>, _>>()?;
    publics.sort_by_key(|k| k.id());
    let policies = core::array::from_fn(|role| {
        let mut mask = 0;
        for (i, key) in keys.iter().enumerate() {
            if (role == 0 && i < 2) || (role > 0 && i == role + 1) {
                mask |= 1
                    << publics
                        .iter()
                        .position(|p| *p == public(key).unwrap())
                        .unwrap();
            }
        }
        RolePolicy {
            mask,
            threshold: if role == 0 { 2 } else { 1 },
            max_validity_secs: LIFETIMES[role],
        }
    });
    let mut payload = vec![0; md::ROOT_BYTES];
    md::encode_root(&mut payload, author.common(), &publics, policies)
        .map_err(|e| format!("development Root: {e:?}"))?;
    let out = signed(Role::Root, &payload, &[&keys[0], &keys[1]])?;
    TrustedRoot::provisioned(&out, binding())
        .map_err(|e| format!("development Root self-quorum: {e:?}"))?;
    Ok(out)
}
fn manifest(a: &Authority) -> Result<serde_json::Value, String> {
    let root =
        TrustedRoot::provisioned(&a.root, binding()).map_err(|e| format!("public Root: {e:?}"))?;
    let keys=a.keys.iter().enumerate().map(|(i,k)|Ok(serde_json::json!({"role":ROLES[i],"public":hex(&public(k)?.bytes()),"id":hex(&public(k)?.id())}))).collect::<Result<Vec<_>,String>>()?;
    Ok(
        serde_json::json!({"schema":1,"authority":"DEVELOPMENT ONLY; not Official Evrosion","bootstrap":"independently provisioned first-party public fixture; server cannot replace it","root_sha256":hex(&digest(&a.root)),"root_version":root.common().version,"not_before":root.common().not_before,"expires":root.common().expires,"author_dates_are_not_utc_acceptance":true,"binding":{"namespace":hex(&binding().namespace),"channel":hex(&binding().channel),"platform":hex(&binding().platform)},"thresholds":[2,1,1,1],"max_validity_seconds":LIFETIMES,"keys":keys}),
    )
}
fn check_dir(path: &Path, mode: Option<u32>) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_dir() || mode.is_some_and(|v| m.permissions().mode() & 0o7777 != v) {
        return Err("development authority directory type/permissions mismatch".into());
    }
    if mode.is_some() && m.uid() != fs::metadata("/proc/self").map_err(|e| e.to_string())?.uid() {
        return Err("development key directory must belong to this host owner".into());
    }
    Ok(())
}
fn directory(root: &Path) -> Result<PathBuf, String> {
    Ok(fs::canonicalize(root)
        .map_err(|e| e.to_string())?
        .join("build/m6/development-signing"))
}
fn public_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())
}
fn read_public(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.len() == 0 || m.len() > max {
        return Err("development public fixture must be bounded regular bytes".into());
    }
    fs::read(path).map_err(|e| e.to_string())
}
/// Explicit one-time provisioning only. Any existing/partial authority refuses;
/// load never calls this, and missing/corrupt keys cannot rotate the anchor.
pub fn provision(root: &Path, author: Author) -> Result<Authority, String> {
    let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    let private = directory(&root)?;
    if fs::symlink_metadata(&private).is_ok()
        || fs::symlink_metadata(root.join(ROOT_FILE)).is_ok()
        || fs::symlink_metadata(root.join(PUBLIC_FILE)).is_ok()
    {
        return Err(
            "development authority already exists or is partial; no automatic regeneration".into(),
        );
    }
    // Validate public author inputs before creating any private key files.
    if author.version != 1
        || author
            .expires
            .checked_sub(author.not_before)
            .is_none_or(|span| span == 0 || span > u64::from(LIFETIMES[0]))
    {
        return Err("initial development Root author validity/version".into());
    }
    for p in [root.join("build"), root.join("build/m6")] {
        if !p.try_exists().map_err(|e| e.to_string())? {
            fs::create_dir(&p).map_err(|e| e.to_string())?;
        }
        check_dir(&p, None)?;
    }
    check_dir(&root.join("tools"), None)?;
    check_dir(&root.join("tools/m6"), None)?;
    check_dir(&root.join("tools/m6/fixtures"), None)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&private)
        .map_err(|e| e.to_string())?;
    check_dir(&private, Some(0o700))?;
    let mut os = File::open("/dev/urandom").map_err(|e| format!("OS CSPRNG: {e}"))?;
    let mut keys = Vec::new();
    for name in NAMES {
        let mut seed = [0; 32];
        let result = (|| {
            os.read_exact(&mut seed)
                .map_err(|e| format!("OS CSPRNG: {e}"))?;
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(private.join(name))
                .map_err(|e| e.to_string())?;
            f.write_all(&seed)
                .and_then(|_| f.sync_all())
                .map_err(|e| e.to_string())?;
            Ok::<_, String>(SigningKey::from_bytes(&seed))
        })();
        seed.zeroize();
        keys.push(result?);
    }
    let keys: [SigningKey; 5] = keys.try_into().map_err(|_| "development key count")?;
    let a = Authority {
        root: root_bytes(&keys, author)?,
        keys,
    };
    public_write(&root.join(ROOT_FILE), &a.root)?;
    let mut json = serde_json::to_vec_pretty(&manifest(&a)?).map_err(|e| e.to_string())?;
    json.push(b'\n');
    public_write(&root.join(PUBLIC_FILE), &json)?;
    File::open(&private)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(a)
}
impl Authority {
    /// Strict load only: no missing/corrupt/wrong key is repaired or replaced.
    pub fn load(root: &Path) -> Result<Self, String> {
        let private = directory(root)?;
        check_dir(&private, Some(0o700))?;
        let mut actual = fs::read_dir(&private)
            .map_err(|e| e.to_string())?
            .map(|e| e.map(|e| e.file_name()).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        actual.sort();
        let mut expected = NAMES.map(std::ffi::OsString::from);
        expected.sort();
        if actual != expected {
            return Err(
                "development signing key set missing or unexpected; no regeneration".into(),
            );
        }
        let uid = fs::metadata(&private).map_err(|e| e.to_string())?.uid();
        let mut keys = Vec::new();
        for name in NAMES {
            let path = private.join(name);
            let before = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            let mut f = File::open(&path).map_err(|e| e.to_string())?;
            let m = f.metadata().map_err(|e| e.to_string())?;
            if !before.is_file()
                || !m.is_file()
                || m.dev() != before.dev()
                || m.ino() != before.ino()
                || m.uid() != uid
                || m.nlink() != 1
                || m.len() != 32
                || m.permissions().mode() & 0o7777 != 0o600
            {
                return Err(
                    "development private key file type/size/owner/permissions mismatch".into(),
                );
            }
            let mut seed = [0; 32];
            let result = f.read_exact(&mut seed);
            let key = SigningKey::from_bytes(&seed);
            seed.zeroize();
            result.map_err(|e| e.to_string())?;
            keys.push(key);
        }
        let keys: [SigningKey; 5] = keys.try_into().map_err(|_| "development key count")?;
        let root_bytes = read_public(&root.join(ROOT_FILE), signature::MAX_ENVELOPE_BYTES as u64)?;
        let trusted = TrustedRoot::provisioned(&root_bytes, binding())
            .map_err(|e| format!("independent development Root: {e:?}"))?;
        let c = trusted.common();
        let expected = root_bytes_from_keys(&keys, c)?;
        if expected != root_bytes {
            return Err(
                "development private keys differ from independent public anchor; no regeneration"
                    .into(),
            );
        }
        let a = Self {
            keys,
            root: root_bytes,
        };
        let public: serde_json::Value =
            serde_json::from_slice(&read_public(&root.join(PUBLIC_FILE), 16384)?)
                .map_err(|e| e.to_string())?;
        if public != manifest(&a)? {
            return Err("development public provenance differs from pinned authority".into());
        }
        Ok(a)
    }
    pub fn root(&self) -> &[u8] {
        &self.root
    }
    /// Returns signed canonical bytes only. Author labels never bypass the
    /// consumer's qualified time, atomic replay, artifact or admission checks.
    pub fn sign(&self, author: Author, targets: &[TargetSpec; 2]) -> Result<SignedRelease, String> {
        self.sign_records(author, targets)
    }
    /// A sequential same-app release has one target, not two variant names.
    pub fn sign_candidate(
        &self,
        author: Author,
        target: TargetSpec,
    ) -> Result<SignedRelease, String> {
        self.sign_records(author, core::slice::from_ref(&target))
    }
    fn sign_records(
        &self,
        author: Author,
        targets: &[TargetSpec],
    ) -> Result<SignedRelease, String> {
        let root =
            TrustedRoot::provisioned(&self.root, binding()).map_err(|e| format!("Root: {e:?}"))?;
        if author.not_before < root.common().not_before
            || author.expires > root.common().expires
            || author
                .expires
                .checked_sub(author.not_before)
                .is_none_or(|n| n == 0 || n > u64::from(LIFETIMES[3]))
        {
            return Err("metadata author interval outside development role policy".into());
        }
        let mut specs = targets.to_vec();
        specs.sort_by_key(|t| t.name);
        let mut p = vec![0; md::HEADER_BYTES + specs.len() * md::TARGET_BYTES];
        md::encode_targets(&mut p, author.common(), &specs)
            .map_err(|e| format!("targets: {e:?}"))?;
        let targets = signed(Role::Targets, &p, &[&self.keys[2]])?;
        let link = |role, key, bytes: &[u8]| -> Result<Vec<u8>, String> {
            let envelope = Envelope::parse(bytes).map_err(|e| format!("link: {e:?}"))?;
            let mut p = vec![0; md::HEADER_BYTES + md::LINK_BYTES];
            md::encode_link(
                &mut p,
                role,
                author.common(),
                Identity::of(&envelope, author.version),
            )
            .map_err(|e| format!("link payload: {e:?}"))?;
            signed(role, &p, &[&self.keys[key]])
        };
        let snapshot = link(Role::Snapshot, 3, &targets)?;
        let timestamp = link(Role::Timestamp, 4, &snapshot)?;
        let result = SignedRelease {
            targets,
            snapshot,
            timestamp,
        };
        result.check_signatures(&self.root)?;
        Ok(result)
    }
}
fn root_bytes_from_keys(keys: &[SigningKey; 5], common: Common) -> Result<Vec<u8>, String> {
    root_bytes(
        keys,
        Author {
            version: common.version,
            not_before: common.not_before,
            expires: common.expires,
        },
    )
}
impl SignedRelease {
    /// Syntax/signature/link consistency only. This deliberately returns no
    /// verifier::Verified, proposed replay state or qualified/freshness result.
    pub fn check_signatures(&self, independently_provisioned_root: &[u8]) -> Result<(), String> {
        let trusted = TrustedRoot::provisioned(independently_provisioned_root, binding())
            .map_err(|e| format!("independent Root: {e:?}"))?;
        let root = md::Root::parse(
            &Envelope::parse(trusted.bytes()).map_err(|e| format!("Root envelope: {e:?}"))?,
        )
        .map_err(|e| format!("Root metadata: {e:?}"))?;
        let t = Envelope::parse(&self.targets).map_err(|e| format!("targets envelope: {e:?}"))?;
        let s = Envelope::parse(&self.snapshot).map_err(|e| format!("snapshot envelope: {e:?}"))?;
        let ts =
            Envelope::parse(&self.timestamp).map_err(|e| format!("timestamp envelope: {e:?}"))?;
        let targets = md::Targets::parse(&t).map_err(|e| format!("targets metadata: {e:?}"))?;
        let snapshot = md::Linked::parse(&s).map_err(|e| format!("snapshot metadata: {e:?}"))?;
        let timestamp = md::Linked::parse(&ts).map_err(|e| format!("timestamp metadata: {e:?}"))?;
        if s.role() != Role::Snapshot
            || ts.role() != Role::Timestamp
            || !snapshot.link().matches(&t, targets.common().version)
            || !timestamp.link().matches(&s, snapshot.common().version)
        {
            return Err("development metadata chain link mismatch".into());
        }
        for (envelope, common) in [
            (t, targets.common()),
            (s, snapshot.common()),
            (ts, timestamp.common()),
        ] {
            if common.binding != binding() || common.root_version != trusted.common().version {
                return Err("development metadata binding/root mismatch".into());
            }
            root.authenticate(&envelope)
                .map_err(|e| format!("development role quorum: {e:?}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
