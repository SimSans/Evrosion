//! Typed actual-artifact V5 bundle. Every measured hash is derived from bytes;
//! planned capability identities are a dry run, never hardware provenance.
use super::{Options, SemanticDeclarations, packages};
use crate::build;
use ev_kernel::{root_producer_v5 as producer, service::ServiceImage};
use ev_userspace_contract::root_v5::{
    self as v5,
    catalogue::{self as cat, PackageBank},
    graph::{self, ImageSlot},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

#[path = "packing.rs"]
mod packing;

/// Independently retained symbol-bearing ELF for the exact same loaded image.
/// This is an explicit analysis input, never the executable sent to the Kernel.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisInput {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub path: PathBuf,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis: Option<AnalysisInput>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileAppPackages {
    pub current: Input,
    pub candidate: Input,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub schema: u16,
    pub root: Input,
    pub shell: Input,
    pub input: Input,
    pub workspace: Input,
    pub block: Input,
    pub display: Input,
    pub net_driver: Input,
    pub net_service: Input,
    pub files: Input,
    pub editor: Input,
    pub inspector: Input,
    #[serde(default)]
    pub editor_candidate: Option<Input>,
    pub workspace_mode: String,
    #[serde(default)]
    pub semantic_tree: SemanticDeclarations,
    #[serde(default)]
    pub file_app_packages: Option<FileAppPackages>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ingress: Option<Input>,
}
impl Inputs {
    fn image(&self, slot: ImageSlot) -> &Input {
        match slot {
            ImageSlot::Shell => &self.shell,
            ImageSlot::Input => &self.input,
            ImageSlot::Workspace => &self.workspace,
            ImageSlot::Block => &self.block,
            ImageSlot::Display => &self.display,
            ImageSlot::NetDriver => &self.net_driver,
            ImageSlot::NetService => &self.net_service,
            ImageSlot::Files => &self.files,
            ImageSlot::Editor => &self.editor,
            ImageSlot::Inspector => &self.inspector,
        }
    }
}
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn hash32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected canonical lowercase SHA256".into());
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    if out == [0; 32] {
        return Err("zero digest is not actual artifact provenance".into());
    }
    Ok(out)
}
pub fn read_elf(path: &Path) -> Result<Vec<u8>, String> {
    let m = fs::symlink_metadata(path).map_err(|e| format!("{}:{e}", path.display()))?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() == 0 || m.len() > 2 * 1024 * 1024 {
        return Err("ELF must be a bounded regular immutable input".into());
    }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if bytes.len() as u64 != m.len() || bytes.len() > 2 * 1024 * 1024 {
        return Err("ELF length changed or exceeds bounded input".into());
    }
    if bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01") {
        return Err("expected actual little-endian ELF64".into());
    }
    Ok(bytes)
}
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{}:{e}", path.display()))?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}
pub fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    write_new(path, &bytes)
}
pub fn new_output(path: &Path) -> Result<PathBuf, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::create_dir(path).map_err(|e| format!("new output {}:{e}", path.display()))?;
    path.canonicalize().map_err(|e| e.to_string())
}
fn load(input: &Input, base: &Path) -> Result<Vec<u8>, String> {
    let path = if input.path.is_absolute() {
        input.path.clone()
    } else {
        base.join(&input.path)
    };
    let bytes = read_elf(&path)?;
    if hash(&bytes) != hash32(&input.sha256)? {
        return Err(format!("actual ELF SHA differs: {}", path.display()));
    }
    Ok(bytes)
}
fn load_package(input: &Input, base: &Path) -> Result<Vec<u8>, String> {
    if input.analysis.is_some() {
        return Err("a Zion package cannot carry an ELF analysis sidecar".into());
    }
    let path = if input.path.is_absolute() {
        input.path.clone()
    } else {
        base.join(&input.path)
    };
    let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > v5::resources::PACKAGE_MAX_BYTES
    {
        return Err("supplied Zion must be a bounded regular actual input".into());
    }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if hash(&bytes) != hash32(&input.sha256)? {
        return Err("supplied Zion SHA differs".into());
    }
    Ok(bytes)
}
fn constant(out: &mut String, name: &str, path: &Path) -> Result<(), String> {
    *out += &format!(
        "pub const {name}:&[u8]=include_bytes!({});\n",
        serde_json::to_string(path).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn digest(out: &mut String, name: &str, value: [u8; 32]) {
    *out += &format!("pub const {name}:[u8;32]={value:?};\n");
}
fn stack(
    root: &Path,
    directory: &Path,
    name: &str,
    path: &Path,
    first: u64,
    pages: u64,
) -> Result<serde_json::Value, String> {
    let report = directory.join(format!("{name}.stack.json"));
    let mut c = Command::new("python3");
    c.current_dir(root)
        .arg(root.join("tools/m5/stack_audit.py"))
        .args(["--userspace", "--stack-bytes"])
        .arg((pages * 4096).to_string())
        .arg("--stack-first-page")
        .arg(first.to_string())
        .arg(path)
        .arg(&report);
    build::logged(&mut c, &directory.join(format!("{name}-stack.log")))?;
    serde_json::from_slice(&fs::read(report).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}
struct StackImage<'a> {
    input: &'a Input,
    bytes: &'a [u8],
    path: &'a Path,
}
fn image_stack(
    root: &Path,
    base: &Path,
    directory: &Path,
    name: &str,
    image: StackImage<'_>,
    stack_layout: (u64, u64),
) -> Result<serde_json::Value, String> {
    let retained =
        packing::retain_analysis(image.input, base, directory, name, image.bytes, image.path)?;
    let mut census = stack(
        root,
        directory,
        name,
        &retained.path,
        stack_layout.0,
        stack_layout.1,
    )?;
    if let Some(equivalence) = retained.equivalence {
        let fields = census
            .as_object_mut()
            .ok_or("stack auditor returned a nonobject report")?;
        fields.insert(
            "actual_elf_sha256".into(),
            serde_json::json!(hex(&hash(image.bytes))),
        );
        fields.insert("analysis_equivalence".into(), equivalence);
        fields.insert(
            "analysis_scope".into(),
            serde_json::json!("Census of an explicitly retained symbol ELF after exact entry, entire program-header table and every literal PT_LOAD byte comparison. Existing census limitations remain unchanged."),
        );
    }
    Ok(census)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    schema: u16,
    purpose: String,
    version: String,
    binary_sha256: String,
    model_source_url: String,
    model_source_sha256: String,
    downstream_equivalence_qualified: bool,
    mac: [u8; 6],
    policy: ReferencePolicy,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferencePolicy {
    allowed_ipv4: [u8; 4],
    remote_port: u16,
    local_port: u16,
    dns_name: String,
}
pub fn command(options: &Options, build_kernel: bool) -> Result<(), String> {
    let root = options.root.canonicalize().map_err(|e| e.to_string())?;
    let input_path = options
        .artifacts
        .as_ref()
        .unwrap()
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let inputs: Inputs = serde_json::from_slice(&fs::read(&input_path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let directory = new_output(options.output.as_ref().unwrap())?;
    prepare(&root, &directory, &input_path, &inputs)?;
    if build_kernel {
        super::run::build_kernel(&root, &directory)?;
    }
    println!("M8 actual bundle: {}", directory.display());
    Ok(())
}
pub fn prepare(
    root: &Path,
    directory: &Path,
    input_path: &Path,
    inputs: &Inputs,
) -> Result<(), String> {
    if inputs.schema != 1 || !matches!(inputs.workspace_mode.as_str(), "open" | "provision-new") {
        return Err("workspace artifact input schema/mode invalid".into());
    }
    let base = input_path.parent().ok_or("artifact input parent missing")?;
    let root_image = load(&inputs.root, base)?;
    write_new(&directory.join("root.elf"), &root_image)?;
    let mut generated = String::from(
        "// Actual measured M8 development inputs; no VM acceptance or authority claim.\n",
    );
    constant(&mut generated, "M8_ROOT_IMAGE", &directory.join("root.elf"))?;
    let mut actual_images: Vec<Vec<u8>> = Vec::new();
    let mut descriptors = Vec::new();
    let mut measurements = Vec::new();
    for slot in graph::IMAGES {
        let bytes = load(inputs.image(slot), base)?;
        let sha = hash(&bytes);
        let descriptor = ServiceImage::verify_m8(&bytes, sha, slot)
            .map_err(|e| format!("M8 {slot:?} typed admission:{e:?}"))?;
        let plan = descriptor
            .plan()
            .map_err(|e| format!("M8 {slot:?} plan:{e:?}"))?;
        let name = format!("{slot:?}");
        let path = directory.join(format!("{name}.elf"));
        write_new(&path, &bytes)?;
        let census = image_stack(
            root,
            base,
            directory,
            &name,
            StackImage {
                input: inputs.image(slot),
                bytes: &bytes,
                path: &path,
            },
            v5::resources::stack(slot),
        )?;
        let row = cat::Image {
            image: sha,
            descriptor: descriptor.digest(),
            abi: v5::child::abi(slot.representative()),
            limits: slot.representative().limits(),
            role_shape: producer::role_shape_digest(slot),
        };
        if plan.required_frames() > slot.representative().limits()[1] {
            return Err(format!("M8 {slot:?} plan exceeds actual Job frame limit"));
        }
        let symbol = match slot {
            ImageSlot::NetDriver => "NET_DRIVER".into(),
            ImageSlot::NetService => "NET_SERVICE".into(),
            _ => name.to_ascii_uppercase(),
        };
        constant(&mut generated, &format!("M8_{symbol}_IMAGE"), &path)?;
        digest(&mut generated, &format!("M8_{symbol}_SHA"), sha);
        measurements.push(serde_json::json!({"slot":name,"sha256":hex(&sha),"descriptor":hex(&row.descriptor),"role_shape":hex(&row.role_shape),"abi":hex(&row.abi),"limits":row.limits,"required_frames":plan.required_frames(),"stack_census":census}));
        descriptors.push(row);
        actual_images.push(bytes);
    }
    let ui =
        hash(&fs::read(root.join("libs/workspace-client/src/ui.rs")).map_err(|e| e.to_string())?);
    let candidate = if let Some(input) = &inputs.editor_candidate {
        load(input, base)?
    } else {
        actual_images[ImageSlot::Editor.index()].clone()
    };
    let candidate_census = if let Some(input) = &inputs.editor_candidate {
        let path = directory.join("EditorCandidate.elf");
        write_new(&path, &candidate)?;
        Some(image_stack(
            root,
            base,
            directory,
            "EditorCandidate",
            StackImage {
                input,
                bytes: &candidate,
                path: &path,
            },
            v5::resources::stack(ImageSlot::Editor),
        )?)
    } else {
        None
    };
    let semantic_source = packages::semantic_source(root)?;
    let supplied = inputs
        .file_app_packages
        .as_ref()
        .map(|pair| {
            Ok::<_, String>([
                load_package(&pair.current, base)?,
                load_package(&pair.candidate, base)?,
            ])
        })
        .transpose()?;
    if supplied.is_some() && inputs.editor_candidate.is_none() {
        return Err("supplied package pair requires both actual current/candidate ELF inputs; no implicit candidate".into());
    }
    let packages = packages::build_four_inputs(
        [
            &actual_images[ImageSlot::Files.index()],
            &actual_images[ImageSlot::Editor.index()],
            &actual_images[ImageSlot::Inspector.index()],
            &candidate,
        ],
        ui,
        inputs.semantic_tree,
        semantic_source,
        supplied
            .as_ref()
            .map(|pair| [pair[0].as_slice(), pair[1].as_slice()]),
    )?;
    let placements = packages::write(directory, &packages)?;
    let package_rows = core::array::from_fn(|i| cat::Package {
        app_id: packages[i].app,
        digest: packages[i].package,
        build: packages[i].build,
        image: packages[i].executable,
        bytes: packages[i].bytes.len() as u64,
        bank: if placements[i].0 == 0 {
            PackageBank::Current
        } else {
            PackageBank::Candidate
        },
        offset: placements[i].1,
    });
    for (i, p) in packages.iter().enumerate() {
        let symbol = match i {
            0 => "FILES",
            1 => "EDITOR",
            2 => "INSPECTOR",
            _ => "EDITOR_CANDIDATE",
        };
        constant(
            &mut generated,
            &format!("M8_PACKAGE_{symbol}"),
            &directory.join(format!("{}.zion", p.kind)),
        )?;
    }
    generated += &format!("pub const M8_PACKAGE_PLACEMENT:[(u8,u32);4]={placements:?};\n");
    let ingress_bytes = inputs
        .external_ingress
        .as_ref()
        .map(|input| load_package(input, base))
        .transpose()?;
    let external_ingress = ingress_bytes
        .as_deref()
        .map(|bytes| packages::external_ingress(bytes, package_rows))
        .transpose()?;
    if let Some(bytes) = ingress_bytes.as_deref() {
        let path = directory.join("ExternalIngress.zion");
        write_new(&path, bytes)?;
        constant(&mut generated, "M8_EXTERNAL_INGRESS_BYTES", &path)?;
        generated +=
            "pub const M8_EXTERNAL_INGRESS:Option<&[u8]>=Some(M8_EXTERNAL_INGRESS_BYTES);\n";
        let record = external_ingress.unwrap();
        write_json_new(
            &directory.join("external-ingress.json"),
            &serde_json::json!({
                "schema":1,"scope":"Measured nonexecuting local-development package input only; no installation, package trust, loaded support or authority",
                "path":path,"package_sha256":hex(&record.package.digest),"app_id":hex(&record.package.app_id),
                "build":hex(&record.package.build),"image":hex(&record.package.image),"bytes":bytes.len(),
                "bank":"Candidate","offset":record.package.offset,"bank_bytes":PackageBank::Candidate.capacity_bytes(),
                "provenance":"LocalOwnerDevelopment","installed":false,"started":false
            }),
        )?;
    } else {
        generated += "pub const M8_EXTERNAL_INGRESS:Option<&[u8]>=None;\n";
    }
    let reference_bytes =
        fs::read(root.join("tools/m6/fixtures/qemu-reference.json")).map_err(|e| e.to_string())?;
    let reference: Reference =
        serde_json::from_slice(&reference_bytes).map_err(|e| e.to_string())?;
    if reference.schema != 1
        || reference.purpose.is_empty()
        || reference.version.is_empty()
        || !reference
            .model_source_url
            .starts_with("https://raw.githubusercontent.com/qemu/qemu/")
        || reference.mac != cat::REFERENCE_MAC
    {
        return Err("pinned reference device witness shape differs".into());
    }
    let device = cat::DeviceWitness {
        mac: reference.mac,
        model_source_sha256: hash32(&reference.model_source_sha256)?,
        emulator_binary_sha256: hash32(&reference.binary_sha256)?,
    };
    let (source, input_rows) = build::source_inputs(root)?;
    let input_hash = hash32(&source)?;
    let graph_hash = hash(&graph::description());
    let layout_hash = hash(&v5::resources::layout_description());
    let encode = |measurement| {
        cat::encode_with_ingress(
            cat::Description {
                root_image: hash(&root_image),
                kernel_input: input_hash,
                graph_measurement: graph_hash,
                layout_measurement: layout_hash,
                measurement,
                boot_mode: cat::BootMode::Standalone,
                restart_attempts: 3,
                restart_window: 60_000,
                images: descriptors.clone().try_into().unwrap(),
                instance_bindings: core::array::from_fn(|i| {
                    producer::instance_binding_digest(graph::CHILDREN[i])
                }),
                packages: package_rows,
                device,
                network: cat::NetworkPolicy {
                    allowed_ipv4: reference.policy.allowed_ipv4,
                    remote_port: reference.policy.remote_port,
                    local_port: reference.policy.local_port,
                    dns_name: &reference.policy.dns_name,
                },
            },
            external_ingress,
        )
        .map_err(|e| format!("M8 catalogue:{e:?}"))
    };
    let draft = encode([1; 32])?;
    let parsed = cat::Catalogue::decode(&draft).map_err(|e| format!("M8 draft catalogue:{e:?}"))?;
    let mut h = Sha256::new();
    h.update(cat::MEASUREMENT_DOMAIN);
    let (a, b) = parsed.measurement_parts();
    h.update(a);
    h.update(b);
    let full = h.finalize().into();
    let catalogue = encode(full)?;
    write_new(&directory.join("catalogue.bin"), &catalogue)?;
    constant(
        &mut generated,
        "M8_CATALOGUE",
        &directory.join("catalogue.bin"),
    )?;
    digest(&mut generated, "M8_CAT_SHA", hash(&catalogue));
    let description = producer::Description::full_graph(
        v5::ROOT_LIMITS,
        3,
        60_000,
        producer::planned_identities()
            .map_err(|e| format!("V5 actual Authority planning:{e:?}"))?,
    )
    .map_err(|e| format!("V5 Root source profile:{e:?}"))?
    .bind_catalogue(hash(&catalogue));
    let encoded = producer::encode_current(&root_image, &description)
        .map_err(|e| format!("V5 Root producer:{e:?}"))?;
    let admitted =
        ev_kernel::root_manifest_v5::verify(encoded.bytes(), encoded.digest(), &root_image)
            .map_err(|e| format!("V5 Root manifest:{e:?}"))?;
    let joined = admitted
        .catalogue(&catalogue)
        .map_err(|e| format!("V5 Root/catalogue join:{e:?}"))?;
    producer::verify_external_ingress(&joined, ingress_bytes.as_deref())
        .map_err(|e| format!("V5 actual ingress join:{e:?}"))?;
    if joined.measurement() != full {
        return Err("V5 full catalogue measurement differs".into());
    }
    let root_plan = ev_kernel::executable::Image::from_root_v5(&admitted)
        .map_err(|e| format!("V5 Root layout:{e:?}"))?;
    let root_frames = root_plan.required_frames();
    let root_census = image_stack(
        root,
        base,
        directory,
        "Root",
        StackImage {
            input: &inputs.root,
            bytes: &root_image,
            path: &directory.join("root.elf"),
        },
        (256, 8),
    )?;
    write_new(&directory.join("root-manifest.bin"), encoded.bytes())?;
    constant(
        &mut generated,
        "M8_ROOT_MANIFEST",
        &directory.join("root-manifest.bin"),
    )?;
    digest(&mut generated, "M8_ROOT_MEASUREMENT", encoded.digest());
    write_new(&directory.join("workspace-bundle.rs"), generated.as_bytes())?;
    write_json_new(&directory.join("input-artifacts.json"), inputs)?;
    write_json_new(
        &directory.join("bundle.json"),
        &serde_json::json!({"schema":1,"status":"Actual typed V5 bundle prepared; no actual VM admission or hardware/authority provenance claim","kernel_feature":"test-m8-workspace-run","root_abi":hex(&v5::ABI),"child_abi":hex(&v5::child::ABI),"root_sha256":hex(&hash(&root_image)),"root_manifest_sha256":hex(&encoded.digest()),"root_authority_dry_run":hex(&description.authority_digest()),"catalogue_sha256":hex(&hash(&catalogue)),"catalogue_measurement":hex(&full),"graph_measurement":hex(&graph_hash),"layout_measurement":hex(&layout_hash),"root_required_frames":root_frames,"root_stack_census":root_census,"producer_ui_source_sha256":hex(&ui),"semantic_tree":inputs.semantic_tree,"producer_semantic_source_sha256":hex(&semantic_source),"source_input_policy":build::SourceInputPolicy::CURRENT,"source_sha256":source,"source_inputs":input_rows,"images":measurements,"package_placements":placements,"external_ingress_present":inputs.external_ingress.is_some(),"supplied_file_app_packages":inputs.file_app_packages.is_some(),"file_app_software":[&packages[1].supplied_software,&packages[3].supplied_software],"candidate_same_executable":packages[1].executable==packages[3].executable,"candidate_stack_census":candidate_census,"candidate_scope":"Distinct actual candidate bytes are preparation only; no signed dynamic update, external install/run or bad-candidate qualification","workspace_mode":inputs.workspace_mode,"reference_version":reference.version,"reference_downstream_equivalence_qualified":reference.downstream_equivalence_qualified}),
    )?;
    Ok(())
}
pub fn rebuild(options: &Options) -> Result<(), String> {
    super::run::rebuild(options)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_ingress_input_is_optional_closed_and_cannot_carry_analysis() {
        let artifact = serde_json::json!({"path":"actual","sha256":"a"});
        let mut value = serde_json::json!({"schema":1,"root":artifact,"shell":artifact,"input":artifact,"workspace":artifact,"block":artifact,"display":artifact,"net_driver":artifact,"net_service":artifact,"files":artifact,"editor":artifact,"inspector":artifact,"workspace_mode":"open"});
        let absent: Inputs = serde_json::from_value(value.clone()).unwrap();
        assert!(absent.external_ingress.is_none());
        assert!(
            serde_json::to_value(absent)
                .unwrap()
                .get("external_ingress")
                .is_none()
        );
        value["external_ingress"] = artifact;
        let present: Inputs = serde_json::from_value(value.clone()).unwrap();
        assert!(present.external_ingress.is_some());
        value["external_ingress"]["install"] = true.into();
        assert!(serde_json::from_value::<Inputs>(value.clone()).is_err());
        value["external_ingress"]
            .as_object_mut()
            .unwrap()
            .remove("install");
        value["external_ingress"]["analysis"] = serde_json::json!({"path":"symbols","sha256":"b"});
        let parsed: Inputs = serde_json::from_value(value).unwrap();
        assert!(
            load_package(parsed.external_ingress.as_ref().unwrap(), Path::new("."))
                .unwrap_err()
                .contains("cannot carry")
        );
    }
    #[test]
    fn manifest_inputs_refuse_unknown_duplicate_and_noncanonical_hashes() {
        for v in ["0".repeat(64), "A".repeat(64), "f".repeat(63)] {
            assert!(hash32(&v).is_err());
        }
        assert!(hash32(&"f".repeat(64)).is_ok());
        assert!(serde_json::from_str::<Input>(r#"{"path":"x","sha256":"a","extra":1}"#).is_err());
        assert!(serde_json::from_str::<Input>(r#"{"path":"x","path":"y","sha256":"a"}"#).is_err());
        assert!(
            serde_json::from_str::<FileAppPackages>(r#"{"current":{"path":"a","sha256":"x"}}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<FileAppPackages>(r#"{"current":{"path":"a","sha256":"x"},"candidate":{"path":"b","sha256":"y"},"claim_installed":true}"#).is_err());
        assert!(
            serde_json::from_str::<FileAppPackages>(
                r#"{"current":{"path":"a","sha256":"x"},"candidate":{"path":"b","sha256":"y"}}"#
            )
            .is_ok()
        );
    }
    #[test]
    fn analysis_sidecars_are_explicit_nonrecursive_elf_inputs_only() {
        let old = r#"{"path":"app.elf","sha256":"a"}"#;
        let input: Input = serde_json::from_str(old).unwrap();
        assert!(input.analysis.is_none());
        assert_eq!(
            serde_json::to_value(&input).unwrap(),
            serde_json::from_str::<serde_json::Value>(old).unwrap()
        );
        let with_analysis =
            r#"{"path":"app.elf","sha256":"a","analysis":{"path":"symbols.elf","sha256":"b"}}"#;
        let input: Input = serde_json::from_str(with_analysis).unwrap();
        assert!(input.analysis.is_some());
        assert!(
            load_package(&input, Path::new("."))
                .unwrap_err()
                .contains("cannot carry")
        );
        for bad in [
            r#"{"path":"a","sha256":"b","analysis":{"path":"s","sha256":"c","analysis":{"path":"r","sha256":"d"}}}"#,
            r#"{"path":"a","sha256":"b","analysis":{"path":"s","sha256":"c","extra":true}}"#,
            r#"{"path":"a","sha256":"b","analysis":{"path":"s","sha256":"c","sha256":"d"}}"#,
            r#"{"path":"a","sha256":"b","analysis":{"path":"s"}}"#,
        ] {
            assert!(serde_json::from_str::<Input>(bad).is_err());
        }
    }
}
