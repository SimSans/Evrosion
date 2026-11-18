//! One source-built retained image and a fresh VM with actual QMP observation.
use crate::{
    boot::{self, DisplayBoot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    graphics_protocol::{self, Reference},
    qmp::Ppm,
    storage,
};
use serde_json::{Value, json};
use std::{fs, path::Path};

const FIXTURE: &str = "m4-display";
fn link(path: &Path, base: &Path) -> Result<Value> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err("display evidence must be a regular file".into());
    }
    Ok(
        json!({"path":path.strip_prefix(base).map_err(|_|"display evidence escaped directory")?,"sha256":build::hash_file(path)?}),
    )
}
fn maybe_link(path: &Path, base: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Ok(_) => link(path, base).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn retain_components(root: &Path, evidence: &Path, manifest: &Manifest) -> Result<Value> {
    let output = root.join("build/m0");
    let mut retained = Vec::new();
    for name in [
        "m4-display-app.elf",
        "m4-display-server.elf",
        "m4-display-app-denied.elf",
        "m4-display-server-denied.elf",
        "m4-display-measurements.json",
    ] {
        let mut matches = manifest
            .supervisor
            .iter()
            .filter(|a| Path::new(&a.path).file_name().is_some_and(|n| n == name));
        let artifact = matches
            .next()
            .ok_or_else(|| format!("missing source-built display artifact {name}"))?;
        if matches.next().is_some() {
            return Err(format!("ambiguous display artifact {name}"));
        }
        let path = build::verify_artifact(&output, artifact)?;
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        let destination = evidence.join(name);
        storage::immutable_new(&destination, &bytes)?;
        retained.push(json!({"build_artifact":artifact,"retained":link(&destination,evidence)?}));
    }
    let record = json!({"schema":1,"build_input_id":manifest.build_id,"kernel":manifest.kernel,"boot_image":manifest.image,"components":retained,
        "binding":"exact source-built immutable fixture inputs; not publisher authentication"});
    storage::json_new(&evidence.join("component-binding.json"), &record)?;
    Ok(record)
}
fn validate_capture(serial: &[u8], build_id: &str, path: &Path) -> Result<Value> {
    let present = graphics_protocol::present(serial, build_id)?
        .ok_or("display run has no complete Present marker")?;
    let record = graphics_protocol::record(serial)?;
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16 * 1024 * 1024 {
        return Err("actual display capture is nonregular or oversized".into());
    }
    let frame = Ppm::parse(fs::read(path).map_err(|e| e.to_string())?)?;
    let reference = Reference::hello()?;
    let pixels = reference.validate(&present, &frame)?;
    let text = std::str::from_utf8(serial).map_err(|_| "display serial not UTF-8")?;
    let framebuffer = text
        .lines()
        .find(|l| l.starts_with("EVROSION_FRAMEBUFFER "))
        .ok_or("display run has no framebuffer record")?;
    let f: Vec<_> = framebuffer.split(' ').collect();
    if f.len() != 6
        || f[1] != "present=true"
        || crate::boot_protocol::canonical_number(f[2], "width")? != present.width as u64
        || crate::boot_protocol::canonical_number(f[3], "height")? != present.height as u64
    {
        return Err("Present/QMP geometry differs from actual boot framebuffer".into());
    }
    Ok(json!({"present":present,"lifecycle":record,"pixels":pixels}))
}

pub fn run() -> Result<()> {
    let current = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = crate::doctor::workspace(&current, None)?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let parent = storage::directory_beneath(&root, Path::new("build/m4/evidence"))?;
    let evidence = build::unique_directory(&parent, "display-surface")?;
    println!("Evidence: {}", evidence.display());
    let manifest_path = evidence.join("manifest.json");
    let mut stage = "build";
    let mut manifest_record = None;
    let mut components = None;
    let mut validation = None;
    let mut boots = 0u64;
    let result: Result<()> = (|| {
        build::build(&BuildOptions {
            root: Some(root.clone()),
            fixture: Some(FIXTURE.into()),
            ..BuildOptions::default()
        })?;
        stage = "retain_manifest";
        let bytes = fs::read(root.join("build/m0/manifest.json")).map_err(|e| e.to_string())?;
        storage::immutable_new(&manifest_path, &bytes)?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        manifest.validate_policy_rows()?;
        if manifest.fixture.as_deref() != Some(FIXTURE) {
            return Err("retained display manifest has the wrong fixture".into());
        }
        manifest_record = Some(
            json!({"record":link(&manifest_path,&evidence)?,"build_id":manifest.build_id,"source_sha256":manifest.source_sha256,"kernel":manifest.kernel,"boot_image":manifest.image}),
        );
        stage = "component_binding";
        components = Some(retain_components(&root, &evidence, &manifest)?);
        stage = "boot";
        boots += 1;
        boot::boot_display(
            &BootOptions {
                root: Some(root.clone()),
                timeout_seconds: 120,
                ..BootOptions::default()
            },
            DisplayBoot {
                manifest: &manifest_path,
                evidence: &evidence,
            },
        )?;
        stage = "independent_scanout_validation";
        let serial =
            fs::read(evidence.join("boot/run-001/serial.log")).map_err(|e| e.to_string())?;
        validation = Some(validate_capture(
            &serial,
            &manifest.build_id,
            &evidence.join("boot/run-001/screen-001.ppm"),
        )?);
        Ok(())
    })();
    let mut artifacts = Vec::new();
    let mut link_error = None;
    for name in [
        "boot/results.json",
        "boot/run-001/result.json",
        "boot/run-001/serial.log",
        "boot/run-001/qemu.stderr.log",
        "boot/run-001/qemu-command.json",
        "boot/run-001/qmp-transcript.json",
        "boot/run-001/graphics-observer.json",
        "boot/run-001/screen-001.ppm",
    ] {
        match maybe_link(&evidence.join(name), &evidence) {
            Ok(Some(value)) => artifacts.push(value),
            Ok(None) => {}
            Err(e) => {
                link_error = Some(e);
                break;
            }
        }
    }
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"display-surface","passed":result.is_ok()&&link_error.is_none(),"last_stage":stage,"error":result.as_ref().err(),"evidence_link_error":link_error,
        "build":manifest_record,"components":components,"expected_boots":1,"boot_invocations":boots,"validation":validation,"artifacts":artifacts,
        "method":"One retained source-built image, one fresh Q35/TCG/OVMF VM, actual private QMP P6 scanout; exact full-frame/surface verification, actual app/display containment and owned lifecycle cleanup. No input/focus/picker/package/full-M4 acceptance claim."}),
    )?;
    println!("Evidence: {}", evidence.display());
    result?;
    if let Some(error) = link_error {
        return Err(error);
    }
    println!(
        "PASS display-surface: actual native userspace surface, device-only Display scanout and contained authority faults, with unmodified QMP capture."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn existing_scanout_is_never_overwritten_or_followed_through_a_symlink() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent = storage::directory_beneath(&root, Path::new("build/test-tmp")).unwrap();
        let d = build::unique_directory(&parent, "graphics-evidence").unwrap();
        let original = d.join("screen.ppm");
        storage::immutable_new(&original, b"actual").unwrap();
        assert!(storage::immutable_new(&original, b"replacement").is_err());
        assert_eq!(fs::read(&original).unwrap(), b"actual");
        #[cfg(unix)]
        {
            let alias = d.join("alias.ppm");
            std::os::unix::fs::symlink(&original, &alias).unwrap();
            assert!(maybe_link(&alias, &d).is_err());
        }
        assert!(maybe_link(&d.join("absent"), &d).unwrap().is_none());
    }
}
