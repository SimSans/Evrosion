//! Separately compiled Host download fixtures. This module has no generated
//! Kernel source, catalogue mutation or include_bytes bank output.
use super::{desktop_graph::stack, desktop_tool, load_identity};
use crate::{build, native_package, toolchain::Toolchain};
use ev_kernel::{scheduler::Limits, service::ServiceImage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Component as PathComponent, Path, PathBuf},
    process::Command,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub label: String,
    pub feature: String,
    pub image: PathBuf,
    pub unstripped: PathBuf,
    pub image_sha256: [u8; 32],
    pub unstripped_sha256: [u8; 32],
    pub descriptor: [u8; 32],
    pub image_pages: usize,
    pub private_frames: u64,
    pub stack_report: PathBuf,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Download {
    pub component: Component,
    pub package: PathBuf,
    pub package_sha256: [u8; 32],
    pub package_id: [u8; 32],
    pub build: [u8; 32],
    pub app: [u8; 16],
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema: u16,
    pub purpose: String,
    pub source_sha256: String,
    pub compiled_into_kernel: bool,
    #[serde(default, skip_serializing_if = "not_document")]
    pub document: bool,
    pub references: [Component; 2],
    pub downloads: [Download; 2],
}
fn not_document(value: &bool) -> bool {
    !*value
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())
}
fn bytes(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.len() == 0 || m.len() > max {
        return Err("download component must be a bounded regular file".into());
    }
    fs::read(path).map_err(|e| e.to_string())
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(crate) fn check_component(row: &Component) -> Result<Vec<u8>, String> {
    let image = bytes(&row.image, 1024 * 1024)?;
    let raw = bytes(&row.unstripped, 16 * 1024 * 1024)?;
    if hash(&image) != row.image_sha256
        || hash(&raw) != row.unstripped_sha256
        || load_identity(&raw)? != load_identity(&image)?
    {
        return Err("fixture component bytes/LOAD identity changed".into());
    }
    let v = ev_userspace_contract::root_v4::graph::Child::App.limits();
    let descriptor = ServiceImage::verify(
        &image,
        hash(&image),
        Limits::new(v[0], v[1], v[2], v[3]),
        &native_package::network_hello_roles(),
    )
    .map_err(|e| format!("fixture component descriptor: {e:?}"))?;
    let plan = descriptor
        .plan()
        .map_err(|e| format!("fixture component plan: {e:?}"))?;
    stack(&plan)?;
    if row.descriptor != descriptor.digest()
        || row.private_frames != plan.required_frames()
        || row.private_frames > v[1]
        || row.image_pages != plan.pages().count()
    {
        return Err("fixture component load/role/frame metadata changed".into());
    }
    Ok(image)
}
fn component(
    root: &Path,
    out: &Path,
    target: &Path,
    toolchain: &Toolchain,
    objcopy: &Path,
    label: &str,
    feature: &str,
) -> Result<(Component, Vec<u8>), String> {
    // This target is created by this call. Existing/global target artifacts
    // cannot satisfy any fixture; the source is actually compiled separately.
    fs::create_dir(target).map_err(|e| e.to_string())?;
    let mut command = Command::new("rustup");
    command.current_dir(root).args(["run", &toolchain.channel, "cargo", "build", "--locked", "--offline", "--release", "-p", "ev-native-hello", "--bin", "ev-native-hello", "--features", feature, "--target", "x86_64-unknown-none", "--target-dir"]).arg(target)
        .env("CARGO_ENCODED_RUSTFLAGS", format!("-C\x1frelocation-model=static\x1f-C\x1fcode-model=large\x1f-C\x1fforce-frame-pointers=yes\x1f-C\x1fdebuginfo=1\x1f-C\x1flink-arg=--no-pie\x1f--cfg\x1fcurve25519_dalek_backend=\"serial\"\x1f--remap-path-prefix={}=/evrosion", root.display()))
        .env("RUSTUP_AUTO_INSTALL", "0");
    if feature.split(',').any(|f| f == "document-workflow") {
        command
            .env("CARGO_PROFILE_RELEASE_OPT_LEVEL", "s")
            .env("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1");
    }
    build::logged(&mut command, &out.join(format!("{label}-build.log")))?;
    let raw = bytes(
        &target.join("x86_64-unknown-none/release/ev-native-hello"),
        16 * 1024 * 1024,
    )?;
    let raw_path = out.join(format!("{label}.unstripped.elf"));
    write_new(&raw_path, &raw)?;
    let image_path = out.join(format!("{label}.elf"));
    let mut strip = Command::new(objcopy);
    strip
        .current_dir(root)
        .arg("--strip-debug")
        .arg(&raw_path)
        .arg(&image_path);
    build::logged(&mut strip, &out.join(format!("{label}-strip.log")))?;
    let image = bytes(&image_path, 1024 * 1024)?;
    if load_identity(&raw)? != load_identity(&image)? {
        return Err("download debug separation changed actual PT_LOAD/entry identity".into());
    }
    let values = ev_userspace_contract::root_v4::graph::Child::App.limits();
    let descriptor = ServiceImage::verify(
        &image,
        hash(&image),
        Limits::new(values[0], values[1], values[2], values[3]),
        &native_package::network_hello_roles(),
    )
    .map_err(|e| format!("download {label} descriptor: {e:?}"))?;
    let plan = descriptor
        .plan()
        .map_err(|e| format!("download {label} load: {e:?}"))?;
    stack(&plan)?;
    if plan.required_frames() > values[1] {
        return Err("download exceeds actual App frame quota".into());
    }
    let report = out.join(format!("{label}.stack.json"));
    let mut audit = Command::new("python3");
    audit
        .current_dir(root)
        .arg(root.join("tools/m5/stack_audit.py"))
        .args(["--userspace", "--stack-bytes", "16384"])
        .arg(&image_path)
        .arg(&report);
    build::logged(&mut audit, &out.join(format!("{label}-stack.log")))?;
    let row = Component {
        label: label.into(),
        feature: feature.into(),
        image: image_path,
        unstripped: raw_path,
        image_sha256: hash(&image),
        unstripped_sha256: hash(&raw),
        descriptor: descriptor.digest(),
        image_pages: plan.pages().count(),
        private_frames: plan.required_frames(),
        stack_report: report,
    };
    Ok((row, image))
}
fn output(root: &Path, directory: &Path) -> Result<(PathBuf, PathBuf), String> {
    let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    let directory = if directory.is_absolute() {
        directory.to_owned()
    } else {
        root.join(directory)
    };
    let relative = directory
        .strip_prefix(root.join("build/m6/downloads"))
        .map_err(|_| "download output must be a new build/m6/downloads child")?;
    if relative.components().count() != 1
        || !matches!(relative.components().next(), Some(PathComponent::Normal(_)))
    {
        return Err("download output requires exactly one new owned directory".into());
    }
    let mut current = root.clone();
    for part in ["build", "m6", "downloads"] {
        current.push(part);
        if !current.try_exists().map_err(|e| e.to_string())? {
            fs::create_dir(&current).map_err(|e| e.to_string())?;
        }
        if !fs::symlink_metadata(&current)
            .map_err(|e| e.to_string())?
            .is_dir()
        {
            return Err("download output ancestry must be actual directories".into());
        }
    }
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    Ok((root, directory))
}
/// Build only Host fixture artifacts. The caller supplies its frozen source
/// pin; both actual source observations must match. No Kernel build is run.
pub fn produce(root: &Path, directory: &Path, expected_source: &str) -> Result<Bundle, String> {
    produce_profile(root, directory, expected_source, false)
}
pub fn produce_document(
    root: &Path,
    directory: &Path,
    expected_source: &str,
) -> Result<Bundle, String> {
    produce_profile(root, directory, expected_source, true)
}
fn produce_profile(
    root: &Path,
    directory: &Path,
    expected_source: &str,
    document: bool,
) -> Result<Bundle, String> {
    let (root, out) = output(root, directory)?;
    let (source, rows) = build::source_inputs(&root)?;
    if source != expected_source {
        return Err("download producer source differs from frozen pin".into());
    }
    write_new(
        &out.join("source-inputs.json"),
        &serde_json::to_vec_pretty(&rows).map_err(|e| e.to_string())?,
    )?;
    let mut source_bytes = [0; 32];
    if source.len() != 64 {
        return Err("source fingerprint must be64hex".into());
    }
    for (i, byte) in source_bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&source[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    let toolchain = Toolchain::load(&root)?;
    let tool = desktop_tool(&root, &out, &toolchain)?;
    let scratch_parent = root.join("build/test-tmp/download-targets");
    fs::create_dir_all(&scratch_parent).map_err(|e| e.to_string())?;
    let scratch = build::unique_directory(&scratch_parent, "cold")?;
    write_new(&out.join("compilation-context.json"), &serde_json::to_vec_pretty(&serde_json::json!({"target_root":scratch,"imported_objects":false,"toolchain":toolchain.channel,"scope":"four cold separately compiled source images; references are comparison only"})).map_err(|e| e.to_string())?)?;
    let (a, _) = component(
        &root,
        &out,
        &scratch.join("reference-a"),
        &toolchain,
        &tool,
        "reference-a",
        if document {
            "native-a,document-workflow"
        } else {
            "native-a,native-session"
        },
    )?;
    let (b, _) = component(
        &root,
        &out,
        &scratch.join("reference-b"),
        &toolchain,
        &tool,
        "reference-b",
        if document {
            "native-b,document-workflow"
        } else {
            "native-b,native-session"
        },
    )?;
    let mut downloads = Vec::new();
    for (label, feature, variant) in [
        (
            "downloaded-b",
            "downloaded-b",
            native_package::Downloaded::B,
        ),
        (
            "downloaded-c",
            "downloaded-c",
            native_package::Downloaded::C,
        ),
    ] {
        let (c, image) = component(
            &root,
            &out,
            &scratch.join(label),
            &toolchain,
            &tool,
            label,
            &if document {
                format!("{feature},document-workflow")
            } else {
                feature.to_owned()
            },
        )?;
        if c.image_sha256 == a.image_sha256 || c.image_sha256 == b.image_sha256 {
            return Err("download unexpectedly aliases a precompiled bank image".into());
        }
        let package = if document {
            native_package::downloaded_document_hello(&image, source_bytes, variant)?
        } else {
            native_package::downloaded_hello(&image, source_bytes, variant)?
        };
        if package.bytes.len() > ev_kernel::dynamic_image::MAX_BYTES {
            return Err("download Zion exceeds actual64-page staging bound".into());
        }
        let path = out.join(format!("{label}.zion"));
        write_new(&path, &package.bytes)?;
        downloads.push(Download {
            component: c,
            package: path,
            package_sha256: hash(&package.bytes),
            package_id: package.package,
            build: package.build,
            app: package.app,
        });
    }
    if downloads[0].component.image_sha256 == downloads[1].component.image_sha256 {
        return Err("download B/C executable identities alias".into());
    }
    if build::source_inputs(&root)?.0 != source {
        return Err("source changed while building downloaded fixtures".into());
    }
    let bundle = Bundle {
        schema: 1,
        purpose: "DEVELOPMENT separately compiled downloadable App B/C; no Official authority or execution claim".into(),
        source_sha256: source,
        compiled_into_kernel: false,
        document,
        references: [a, b],
        downloads: downloads.try_into().map_err(|_| "download shape")?,
    };
    write_new(
        &out.join("download-manifest.json"),
        &serde_json::to_vec_pretty(&bundle).map_err(|e| e.to_string())?,
    )?;
    Ok(bundle)
}
