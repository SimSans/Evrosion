//! External Internal applications. A claimed AppId and a selected six-role
//! resource shape are separate from built-in identity and actual installation.
use super::{bundle, packages, run};
use crate::{build, toolchain::Toolchain};
use ev_kernel::service::ServiceImage;
use ev_userspace_contract::root_v5::{self as v5, graph::ImageSlot};
use ev_zion::{
    AppId, Capability, CapabilityRequest, Contract, ContractSupport, Contracts, DataSchema,
    Package, Platform, Version,
    producer::{Resource, Spec},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
pub const HELP: &str = "Usage: ev app create --root SDK --output NEW_PROJECT --app-id ev.example.application --name NAME [--entry cargo-bin] [--profile workspace-private-data-app@1]\n       ev app build --root SDK --project PROJECT --output NEW_BUILD\n       ev app package --root SDK --project PROJECT --built BUILD --output NEW_PACKAGE_DIR\n       ev app verify --root SDK --package APP.zion [--output NEW_REPORT]\n       ev app install|run --root SDK --package APP.zion --output NEW_PREFLIGHT\nThe default selected-file-app profile has no namespace/AppPrivateData grant. The explicit private-data profile requires ND@1 and AppPrivateData but packaging allocates nothing. Install/run retain a verified preflight and refuse until the actual protected Root factory/instance bridge is available. No host execution substitutes for guest admission.\n";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    schema: u16,
    name: String,
    app_id: String,
    version: [u32; 3],
    maturity: String,
    profile: String,
    entry: String,
    max_file_bytes: u32,
    selection: String,
    data: String,
    build_scope: String,
    qualification: String,
}
const LARGE_PROFILE: &str = "workspace-large-io-qualification@1";
const PRIVATE_PROFILE: &str = "workspace-private-data-app@1";
impl Project {
    fn private_data(&self) -> bool {
        self.profile == PRIVATE_PROFILE
    }
    fn validate(&self) -> Result<(), String> {
        if self.schema != 1
            || self.maturity != "Internal"
            || !matches!(
                (self.profile.as_str(), self.max_file_bytes),
                ("workspace-selected-file-app@1", 256)
                    | (LARGE_PROFILE, 1_048_576)
                    | (PRIVATE_PROFILE, 0)
            )
            || self.selection
                != if self.private_data() {
                    "none; private-data only"
                } else {
                    "exact owner-selected route only"
                }
        {
            return Err(
                "unsupported external app profile; metadata does not allocate authority".into(),
            );
        }
        if self.name.is_empty()
            || self.name.len() > 64
            || self.name.chars().any(|c| {
                c.is_control() || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
            })
        {
            return Err("app display name refused".into());
        }
        if self.app_id.len() > 96
            || self.app_id.split('.').count() < 2
            || self.app_id.split('.').any(|s| {
                s.is_empty()
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            || self.app_id.starts_with("evrosion.internal.")
        {
            return Err("app_id must be a distinct canonical reverse-domain claim".into());
        }
        if self.entry.is_empty()
            || self.entry.len() > 48
            || !self
                .entry
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !self.entry.as_bytes()[0].is_ascii_lowercase()
        {
            return Err("entry must be a bounded lower-case Cargo binary name".into());
        }
        if self.data.len() > 1024
            || self.build_scope.len() > 1024
            || self.qualification.len() > 1024
        {
            return Err("project description too large".into());
        }
        Ok(())
    }
    fn id(&self) -> AppId {
        let mut b = b"evrosion.workspace.external.application-id.v1\0".to_vec();
        b.extend_from_slice(self.app_id.as_bytes());
        let hash = bundle::hash(&b);
        AppId::new(hash[..16].try_into().unwrap()).unwrap()
    }
}
fn regular(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let m = fs::symlink_metadata(path).map_err(|e| format!("{}:{e}", path.display()))?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() == 0 || m.len() > max {
        return Err("expected bounded regular input".into());
    }
    fs::read(path).map_err(|e| e.to_string())
}
fn project(path: &Path) -> Result<Project, String> {
    let p: Project = serde_json::from_slice(&regular(&path.join("ev-workspace.json"), 8192)?)
        .map_err(|e| e.to_string())?;
    p.validate()?;
    Ok(p)
}
fn inventory(root: &Path, dirs: &[&str]) -> Result<(String, BTreeMap<String, String>), String> {
    fn walk(base: &Path, p: &Path, rows: &mut BTreeMap<String, String>) -> Result<(), String> {
        let m = fs::symlink_metadata(p).map_err(|e| e.to_string())?;
        if m.file_type().is_symlink() {
            return Err("source inventory rejects symlinks".into());
        }
        if m.is_dir() {
            let mut children = fs::read_dir(p)
                .map_err(|e| e.to_string())?
                .map(|v| v.map(|e| e.path()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            children.sort();
            for p in children {
                walk(base, &p, rows)?;
            }
        } else if m.is_file() {
            if rows.len() > 4096 || m.len() > 4 * 1024 * 1024 {
                return Err("source inventory exceeds bounded profile".into());
            }
            rows.insert(
                p.strip_prefix(base)
                    .map_err(|e| e.to_string())?
                    .to_str()
                    .ok_or("source path must be UTF8")?
                    .into(),
                build::hash_file(p)?,
            );
        } else {
            return Err("source input must be regular".into());
        }
        Ok(())
    }
    let mut rows = BTreeMap::new();
    for d in dirs {
        let p = root.join(d);
        if p.exists() {
            walk(root, &p, &mut rows)?;
        }
    }
    let bytes = serde_json::to_vec(&rows).map_err(|e| e.to_string())?;
    Ok((bundle::hex(&bundle::hash(&bytes)), rows))
}
fn project_inputs(p: &Path) -> Result<(String, BTreeMap<String, String>), String> {
    inventory(
        p,
        &[
            "Cargo.toml",
            "Cargo.lock",
            "build.rs",
            "src",
            "ev-workspace.json",
            "rust-toolchain.toml",
        ],
    )
}
fn sdk_inputs(p: &Path) -> Result<(String, BTreeMap<String, String>), String> {
    inventory(
        p,
        &[
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "libs/workspace-client",
            "libs/userspace-contract",
            "libs/userspace-runtime",
            "libs/graphics",
        ],
    )
}
fn profile_sdk_inputs(
    root: &Path,
    project: &Project,
) -> Result<(String, BTreeMap<String, String>), String> {
    if !project.private_data() {
        return sdk_inputs(root);
    }
    inventory(
        root,
        &[
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo",
            "libs/workspace-client",
            "libs/userspace-contract",
            "libs/userspace-runtime",
            "libs/graphics",
        ],
    )
}
struct Args {
    command: String,
    root: PathBuf,
    values: BTreeMap<String, PathBuf>,
    app_id: Option<String>,
    name: Option<String>,
    entry: Option<String>,
    profile: Option<String>,
}
fn parse(args: &[OsString]) -> Result<Args, String> {
    let command = args
        .first()
        .and_then(|s| s.to_str())
        .filter(|s| {
            matches!(
                *s,
                "create" | "build" | "package" | "verify" | "install" | "run"
            )
        })
        .ok_or(HELP)?
        .to_owned();
    let mut values = BTreeMap::new();
    let mut text = BTreeMap::new();
    let mut it = args[1..].iter();
    while let Some(k) = it.next() {
        let k = k.to_str().ok_or("app flag must be UTF8")?;
        let v = it
            .next()
            .filter(|v| !v.is_empty())
            .ok_or("app option requires value")?;
        if matches!(k, "--app-id" | "--name" | "--entry" | "--profile") {
            if text
                .insert(
                    k.to_owned(),
                    v.to_str().ok_or("app text must be UTF8")?.to_owned(),
                )
                .is_some()
            {
                return Err("duplicate app text option".into());
            }
        } else if matches!(
            k,
            "--root" | "--output" | "--project" | "--built" | "--package"
        ) {
            if values.insert(k.to_owned(), PathBuf::from(v)).is_some() {
                return Err("duplicate app path option".into());
            }
        } else {
            return Err(format!("unknown app option {k}"));
        }
    }
    let allowed: &[&str] = match command.as_str() {
        "create" => &[
            "--root",
            "--output",
            "--app-id",
            "--name",
            "--entry",
            "--profile",
        ],
        "build" => &["--root", "--project", "--output"],
        "package" => &["--root", "--project", "--built", "--output"],
        _ => &["--root", "--package", "--output"],
    };
    if values
        .keys()
        .chain(text.keys())
        .any(|k| !allowed.contains(&k.as_str()))
    {
        return Err("app option does not apply".into());
    }
    let root = values
        .remove("--root")
        .ok_or("explicit --root SDK required")?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    for key in match command.as_str() {
        "create" => &["--output"][..],
        "build" => &["--project", "--output"][..],
        "package" => &["--project", "--built", "--output"][..],
        "verify" => &["--package"][..],
        _ => &["--package", "--output"][..],
    } {
        if !values.contains_key(*key) {
            return Err(format!("{command} requires {key}"));
        }
    }
    Ok(Args {
        command,
        root,
        values,
        app_id: text.remove("--app-id"),
        name: text.remove("--name"),
        entry: text.remove("--entry"),
        profile: text.remove("--profile"),
    })
}
pub fn execute(args: &[OsString]) -> Result<(), String> {
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h")) {
        print!("{HELP}");
        return Ok(());
    }
    let a = parse(args)?;
    match a.command.as_str() {
        "create" => create(&a),
        "build" => build_app(&a),
        "package" => package(&a),
        _ => verify_command(&a),
    }
}
fn create(a: &Args) -> Result<(), String> {
    let profile = a
        .profile
        .as_deref()
        .unwrap_or("workspace-selected-file-app@1");
    if !matches!(profile, "workspace-selected-file-app@1" | PRIVATE_PROFILE) {
        return Err(
            "create supports only the selected-file or explicit private-data profile".into(),
        );
    }
    let private = profile == PRIVATE_PROFILE;
    let p=Project{schema:1,name:a.name.clone().ok_or("create requires --name")?,app_id:a.app_id.clone().ok_or("create requires --app-id")?,version:[0,1,0],maturity:"Internal".into(),profile:profile.into(),entry:a.entry.clone().unwrap_or_else(||"ev-user-file-app".into()),max_file_bytes:if private {0}else{256},selection:if private {"none; private-data only"}else{"exact owner-selected route only"}.into(),data:if private {"Root-owned schema1 private u32; one Read, optional changed Set2026; allocation requires protected Root Install then separate Run"}else{"process-private scratch and exact selected file; automatic durable private namespace not implemented"}.into(),build_scope:"Standalone public SDK source; no private Root implementation dependency".into(),qualification:"Created source only; no build, installation or runtime qualification".into()};
    p.validate()?;
    let d = bundle::new_output(&a.values["--output"])?;
    fs::create_dir(d.join("src")).map_err(|e| e.to_string())?;
    let mut cargo = format!(
        "[package]\nname = {:?}\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n[workspace]\n[[bin]]\nname = {:?}\npath = \"src/main.rs\"\ntest = false\nbench = false\n[dependencies]\n",
        p.entry, p.entry
    );
    for (name, path) in [
        ("ev-workspace-client", "libs/workspace-client"),
        ("ev-userspace-contract", "libs/userspace-contract"),
        ("ev-userspace-runtime", "libs/userspace-runtime"),
        ("ev-graphics", "libs/graphics"),
    ] {
        cargo += &format!(
            "{name} = {{ path = {} }}\n",
            serde_json::to_string(&a.root.join(path)).map_err(|e| e.to_string())?
        );
    }
    cargo += &format!(
        "[build-dependencies]\nev-workspace-client = {{ path = {} }}\n[profile.release]\npanic = \"abort\"\nopt-level = \"s\"\nlto = false\ncodegen-units = 1\ndebug = 1\n",
        serde_json::to_string(&a.root.join("libs/workspace-client")).map_err(|e| e.to_string())?
    );
    bundle::write_new(&d.join("Cargo.toml"), cargo.as_bytes())?;
    bundle::write_new(
        &d.join("src/main.rs"),
        if private {
            include_bytes!("../../templates/private-data-app/main.rs")
        } else {
            include_bytes!("../../templates/selected-file-app/main.rs")
        },
    )?;
    bundle::write_new(
        &d.join("build.rs"),
        include_str!("../../templates/selected-file-app/build.rs")
            .replace("__EV_ENTRY__", &p.entry)
            .as_bytes(),
    )?;
    bundle::write_new(
        &d.join("rust-toolchain.toml"),
        format!(
            "[toolchain]\nchannel = {:?}\nprofile = \"minimal\"\n",
            Toolchain::load(&a.root)?.channel
        )
        .as_bytes(),
    )?;
    bundle::write_json_new(&d.join("ev-workspace.json"), &p)?;
    let readme: &[u8] = if private {
        b"# External private-data SDK app\n\nRequires File2.1 staged verification, ND@1 and AppPrivateData schema1. It requests no selected-file read/edit permissions. After protected Root Install and a separate Run, the app reads its private value, sets2026 only when different, and waits for the exact reply. A later Run reads2026 and skips Set. Package verification establishes no allocation, install, publisher trust or runtime success. Accepted or unknown exchanges are retained without retry.\n"
    } else {
        b"# External selected-file SDK app\n\nUses only the public six-role SDK profile. Read verifies at most256 bytes; edit probing is denied or stages original metadata then aborts under the same cut. No new contents or private namespace are published. Package identity is a claim; installation and runtime require the actual signed Root factory/instance bridge.\n"
    };
    bundle::write_new(&d.join("README.md"), readme)?;
    let mut c = Command::new("rustup");
    c.current_dir(&d)
        .args([
            "run",
            &Toolchain::load(&a.root)?.channel,
            "cargo",
            "generate-lockfile",
            "--offline",
            "--manifest-path",
        ])
        .arg(d.join("Cargo.toml"));
    build::logged(&mut c, &d.join("lock-generate.log"))?;
    bundle::write_json_new(
        &d.join("create.json"),
        &serde_json::json!({"scope":"Created standalone external app source and offline project lock; no kernel authority or installation","claimed_app_id":bundle::hex(&p.id().bytes()),"project":d,"lock_sha256":build::hash_file(&d.join("Cargo.lock"))?}),
    )?;
    println!("Created external app {}", d.display());
    Ok(())
}
fn build_app(a: &Args) -> Result<(), String> {
    let pdir = a.values["--project"]
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let p = project(&pdir)?;
    let d = bundle::new_output(&a.values["--output"])?;
    run::free(&d, 128 * 1024 * 1024)?;
    if !pdir.join("Cargo.lock").exists() {
        let mut c = Command::new("rustup");
        c.current_dir(&pdir)
            .args([
                "run",
                &Toolchain::load(&a.root)?.channel,
                "cargo",
                "generate-lockfile",
                "--offline",
                "--manifest-path",
            ])
            .arg(pdir.join("Cargo.toml"));
        build::logged(&mut c, &d.join("lock-generate.log"))?;
    }
    regular(&pdir.join("Cargo.lock"), 256 * 1024)?;
    let (project_sha, project_rows) = project_inputs(&pdir)?;
    let (sdk_sha, sdk_rows) = profile_sdk_inputs(&a.root, &p)?;
    let target = run::target(&a.root)?;
    let mut c = run::cargo(&a.root, &target)?;
    c.args(["--manifest-path"])
        .arg(pdir.join("Cargo.toml"))
        .args([
            "--release",
            "--target",
            "x86_64-unknown-none",
            "--bin",
            &p.entry,
        ])
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            format!(
                "{}\x1f--remap-path-prefix={}=/application",
                run::flags(&a.root, false),
                pdir.display()
            ),
        );
    build::logged(&mut c, &d.join("app-build.log"))?;
    let full = d.join("application.full.elf");
    fs::copy(
        target.join("x86_64-unknown-none/release").join(&p.entry),
        &full,
    )
    .map_err(|e| e.to_string())?;
    let image = run::strip(&a.root, &d, "application", &full)?;
    let bytes = bundle::read_elf(&image)?;
    let admitted = ServiceImage::verify_m8(&bytes, bundle::hash(&bytes), ImageSlot::Editor)
        .map_err(|e| format!("public selected-file-app typed envelope:{e:?}"))?;
    let mut c = Command::new("python3");
    c.current_dir(&a.root)
        .arg(a.root.join("tools/m5/stack_audit.py"))
        .args([
            "--userspace",
            "--stack-bytes",
            "32768",
            "--stack-first-page",
            "480",
        ])
        .arg(&image)
        .arg(d.join("application.stack.json"));
    build::logged(&mut c, &d.join("app-stack.log"))?;
    if project_inputs(&pdir)?.0 != project_sha || profile_sdk_inputs(&a.root, &p)?.0 != sdk_sha {
        return Err("external project/SDK source changed during build; inputs retained".into());
    }
    bundle::write_json_new(
        &d.join("build.json"),
        &serde_json::json!({"schema":1,"scope":"Actual standalone public selected-file-app ELF; shape admission is not installation/mapping/authority proof","project":pdir,"project_metadata":p,"claimed_app_id":bundle::hex(&p.id().bytes()),"project_sha256":project_sha,"project_sources":project_rows,"sdk_sha256":sdk_sha,"sdk_sources":sdk_rows,"elf_sha256":bundle::hex(&bundle::hash(&bytes)),"descriptor_sha256":bundle::hex(&admitted.digest()),"factory_shape":"selected-file-app6; same closed resource envelope as ImageSlotEditor, distinct application identity","required_frames":admitted.plan().map_err(|e|format!("app plan:{e:?}"))?.required_frames(),"installed":false,"run":false}),
    )?;
    println!("Built external app {}", d.display());
    Ok(())
}
fn contracts() -> [Contract<'static>; 3] {
    [
        Contract {
            name: "ev.internal.file",
            major: 2,
            minimum_minor: 0,
            features: 0,
        },
        Contract {
            name: "ev.internal.surface-present",
            major: 5,
            minimum_minor: 0,
            features: 0,
        },
        Contract {
            name: packages::UI_CONTRACT,
            major: 1,
            minimum_minor: 0,
            features: 0,
        },
    ]
}
fn caps() -> [CapabilityRequest; 4] {
    [
        CapabilityRequest {
            capability: Capability::SelectedFileRead,
            required: false,
        },
        CapabilityRequest {
            capability: Capability::OwnSurfacePresent,
            required: true,
        },
        CapabilityRequest {
            capability: Capability::FocusedInput,
            required: true,
        },
        CapabilityRequest {
            capability: Capability::SelectedFileEdit,
            required: false,
        },
    ]
}
fn project_contracts(project: &Project) -> Vec<Contract<'static>> {
    if !project.private_data() {
        return contracts().to_vec();
    }
    let mut requirements = vec![Contract {
        name: ev_userspace_contract::app_data::INTERFACE,
        major: u16::from(ev_userspace_contract::app_data::VERSION),
        minimum_minor: 0,
        features: 0,
    }];
    requirements.extend(contracts());
    let file = requirements
        .iter_mut()
        .find(|r| r.name == "ev.internal.file")
        .unwrap();
    file.minimum_minor = 1;
    file.features = ev_userspace_contract::file_v2::FEATURE_STAGED_VERIFY;
    requirements
}
fn project_caps(project: &Project) -> Vec<CapabilityRequest> {
    if !project.private_data() {
        return caps().to_vec();
    }
    [
        Capability::AppPrivateData,
        Capability::OwnSurfacePresent,
        Capability::FocusedInput,
    ]
    .map(|capability| CapabilityRequest {
        capability,
        required: true,
    })
    .to_vec()
}
/// Checks the explicit SDK profile's known protocol requirements only. This
/// does not describe any loaded Root or grant AppPrivateData permission.
struct ProfileContracts {
    private_data: bool,
}
impl Contracts for ProfileContracts {
    fn supported(&self, name: &str, major: u16) -> Option<ContractSupport> {
        if self.private_data
            && name == ev_userspace_contract::app_data::INTERFACE
            && major == u16::from(ev_userspace_contract::app_data::VERSION)
        {
            Some(ContractSupport {
                minor: 0,
                features: 0,
            })
        } else {
            packages::Supported.supported(name, major)
        }
    }
}
fn package(a: &Args) -> Result<(), String> {
    let pdir = a.values["--project"]
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let p = project(&pdir)?;
    let built = a.values["--built"]
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let info: serde_json::Value =
        serde_json::from_slice(&regular(&built.join("build.json"), 2 * 1024 * 1024)?)
            .map_err(|e| e.to_string())?;
    if info["project_sha256"].as_str() != Some(project_inputs(&pdir)?.0.as_str())
        || info["sdk_sha256"].as_str() != Some(profile_sdk_inputs(&a.root, &p)?.0.as_str())
    {
        return Err("project/SDK differs from actual build receipt".into());
    }
    let bytes = bundle::read_elf(&built.join("application.elf"))?;
    if info["elf_sha256"].as_str() != Some(bundle::hex(&bundle::hash(&bytes)).as_str()) {
        return Err("external ELF differs from actual build receipt".into());
    }
    let descriptor = ServiceImage::verify_m8(&bytes, bundle::hash(&bytes), ImageSlot::Editor)
        .map_err(|e| format!("app selected factory:{e:?}"))?
        .digest();
    let metadata = serde_json::to_vec(&p).map_err(|e| e.to_string())?;
    let ui = bundle::hash(
        &fs::read(a.root.join("libs/workspace-client/src/ui.rs")).map_err(|e| e.to_string())?,
    );
    let requirement = project_contracts(&p);
    let permissions = project_caps(&p);
    let entry = format!("bin/{}.elf", p.entry);
    let source = format!("External SDK ELF {}", bundle::hex(&bundle::hash(&bytes)));
    let make = |id| {
        ev_zion::producer::build(
            &Spec {
                app: p.id(),
                name: &p.name,
                source: &source,
                publisher: None,
                version: Version {
                    major: p.version[0],
                    minor: p.version[1],
                    patch: p.version[2],
                },
                build_id: id,
                platform: Platform {
                    minimum: 1,
                    target: 1,
                },
                abi: v5::child::abi(ImageSlot::Editor.representative()),
                data_schema: DataSchema {
                    current: 1,
                    oldest_readable: 1,
                },
                entrypoint: &entry,
                contracts: &requirement,
                capabilities: &permissions,
            },
            &bytes,
            &[
                Resource {
                    path: "res/descriptor.sha256",
                    bytes: &descriptor,
                },
                Resource {
                    path: "res/producer-ui-source.sha256",
                    bytes: &ui,
                },
                Resource {
                    path: "res/project.json",
                    bytes: &metadata,
                },
            ],
        )
        .map_err(|e| format!("external Zion encode:{e:?}"))
    };
    let draft = make([1; 32])?;
    let mut material = b"evrosion.workspace.external.package-content.v1\0".to_vec();
    material.extend_from_slice(&draft);
    let package = make(bundle::hash(&material))?;
    let report = verify_bytes(&package)?;
    let d = bundle::new_output(&a.values["--output"])?;
    bundle::write_new(&d.join("application.zion"), &package)?;
    bundle::write_json_new(&d.join("package.json"), &report)?;
    println!(
        "Packaged distinct external app {}",
        d.join("application.zion").display()
    );
    Ok(())
}
pub(super) fn verify_bytes(bytes: &[u8]) -> Result<serde_json::Value, String> {
    let p = Package::parse(bytes).map_err(|e| format!("external package syntax:{e:?}"))?;
    let resource = p
        .resources()
        .find(|r| r.path == "res/project.json")
        .ok_or("external project identity resource absent")?;
    let project: Project = serde_json::from_slice(resource.bytes).map_err(|e| e.to_string())?;
    project.validate()?;
    p.check_requirements(
        1,
        v5::child::abi(ImageSlot::Editor.representative()),
        &ProfileContracts {
            private_data: project.private_data(),
        },
    )
    .map_err(|e| format!("external SDK profile requirements:{e:?}"))?;
    let app = p.app();
    if app.claimed_app != project.id()
        || app.display_name != project.name
        || app.entrypoint != format!("bin/{}.elf", project.entry)
        || app.version
            != (Version {
                major: project.version[0],
                minor: project.version[1],
                patch: project.version[2],
            })
        || app.contracts().collect::<Vec<_>>() != project_contracts(&project)
        || app.capability_requests().collect::<Vec<_>>() != project_caps(&project)
    {
        return Err("external identity/permission/profile readback differs".into());
    }
    let executable = p.executable().bytes;
    let admitted = ServiceImage::verify_m8(executable, bundle::hash(executable), ImageSlot::Editor)
        .map_err(|e| format!("external selected file factory shape:{e:?}"))?;
    let descriptor = p
        .resources()
        .find(|r| r.path == "res/descriptor.sha256")
        .ok_or("measured descriptor resource absent")?;
    if descriptor.bytes != admitted.digest() {
        return Err("external descriptor resource mismatch".into());
    }
    Ok(
        serde_json::json!({"schema":1,"scope":"Verified real external package bytes and selected six-role resource shape; no installation/runtime authority proof","name":app.display_name,"logical_app_id":project.app_id,"claimed_app_id":bundle::hex(&app.claimed_app.bytes()),"package_sha256":bundle::hex(&p.id().bytes()),"build_id":bundle::hex(&app.build_id),"version":project.version,"executable_sha256":bundle::hex(&bundle::hash(executable)),"descriptor_sha256":bundle::hex(&admitted.digest()),"bytes":bytes.len(),"max_file_bytes":project.max_file_bytes,"startup_profile":project.profile,"factory_shape":"selected-file-app6 (ImageSlotEditor envelope); NOT built-in Editor identity","selection":"Only an actual owner-selected endpoint/caller/lease fixes object/rights","app_private_namespace_provisioned":false,"private_data_required":project.private_data(),"contract_support_scope":"Explicit SDK profile only; actual Root loaded support/enrollment remains separate","publisher_claim_present":app.publisher.is_some(),"signature_verified":false,"installed":false,"running":false}),
    )
}
fn verify_command(a: &Args) -> Result<(), String> {
    let bytes = regular(&a.values["--package"], ev_zion::MAX_BYTES as u64)?;
    let report = verify_bytes(&bytes)?;
    if let Some(out) = a.values.get("--output") {
        let d = bundle::new_output(out)?;
        bundle::write_json_new(&d.join("verification.json"), &report)?;
        if matches!(a.command.as_str(), "install" | "run") {
            bundle::write_json_new(
                &d.join("request.json"),
                &serde_json::json!({"operation":a.command,"package":report,"status":"NOT_APPLIED","requires":"Actual protected Root factory admission, correct AppId/instance delivery, independent permission/enrollment and real endpoint grants","reason":"Host CLI performs verified preflight only; protected native Root Install and separate Run are required"}),
            )?;
            return Err(format!(
                "{} not applied: actual signed Root external-app bridge unavailable; verified preflight {}",
                a.command,
                d.display()
            ));
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn private_project() -> Project {
        Project {
            schema: 1,
            name: "Private probe".into(),
            app_id: "ev.example.private-probe".into(),
            version: [0, 1, 0],
            maturity: "Internal".into(),
            profile: PRIVATE_PROFILE.into(),
            entry: "private-probe".into(),
            max_file_bytes: 0,
            selection: "none; private-data only".into(),
            data: "one private u32".into(),
            build_scope: "SDK fixture".into(),
            qualification: "unqualified".into(),
        }
    }
    fn profile_fixture(
        project: &Project,
        requirements: &[Contract<'_>],
        permissions: &[CapabilityRequest],
    ) -> Vec<u8> {
        // Real canonical ELF/container fixture for metadata policy only. It is
        // never executed or treated as native SDK implementation evidence.
        let mut image = vec![0; 8192];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2u16), (18, 62), (52, 64), (54, 56), (56, 2)] {
            image[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        image[20..24].copy_from_slice(&1u32.to_le_bytes());
        for (at, value) in [(24, (1u64 << 39) + 4096), (32, 64)] {
            image[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (index, (page, pages)) in [(1u64, 1u64), (480, 8)].into_iter().enumerate() {
            let at = 64 + index * 56;
            image[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
            image[at + 4..at + 8]
                .copy_from_slice(&(if index == 0 { 5u32 } else { 6 }).to_le_bytes());
            for (offset, value) in [
                (8, if index == 0 { 4096 } else { 8192 }),
                (16, (1u64 << 39) + page * 4096),
                (32, u64::from(index == 0)),
                (40, pages * 4096),
                (48, 4096),
            ] {
                image[at + offset..at + offset + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        image[4096] = 0xc3;
        let descriptor = ServiceImage::verify_m8(&image, bundle::hash(&image), ImageSlot::Editor)
            .unwrap()
            .digest();
        let metadata = serde_json::to_vec(project).unwrap();
        let entry = format!("bin/{}.elf", project.entry);
        ev_zion::producer::build(
            &Spec {
                app: project.id(),
                name: &project.name,
                source: "Canonical SDK metadata test",
                publisher: None,
                version: Version {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
                build_id: [87; 32],
                platform: Platform {
                    minimum: 1,
                    target: 1,
                },
                abi: v5::child::abi(ImageSlot::Editor.representative()),
                data_schema: DataSchema {
                    current: 1,
                    oldest_readable: 1,
                },
                entrypoint: &entry,
                contracts: requirements,
                capabilities: permissions,
            },
            &image,
            &[
                Resource {
                    path: "res/descriptor.sha256",
                    bytes: &descriptor,
                },
                Resource {
                    path: "res/producer-ui-source.sha256",
                    bytes: &[88; 32],
                },
                Resource {
                    path: "res/project.json",
                    bytes: &metadata,
                },
            ],
        )
        .unwrap()
    }
    #[test]
    fn private_profile_is_explicit_and_does_not_widen_default_selected_profile() {
        let mut project = private_project();
        project.validate().unwrap();
        let requirements = project_contracts(&project);
        let permissions = project_caps(&project);
        assert_eq!(requirements.len(), 4);
        let file = requirements
            .iter()
            .find(|r| r.name == "ev.internal.file")
            .unwrap();
        assert_eq!(
            (file.major, file.minimum_minor, file.features),
            (2, 1, ev_userspace_contract::file_v2::FEATURE_STAGED_VERIFY)
        );
        assert!(
            permissions
                .iter()
                .any(|r| r.required && r.capability == Capability::AppPrivateData)
        );
        assert!(permissions.iter().all(|r| r.required
            && !matches!(
                r.capability,
                Capability::SelectedFileRead | Capability::SelectedFileEdit
            )));
        assert!(
            packages::Supported
                .supported(ev_userspace_contract::app_data::INTERFACE, 1)
                .is_none()
        );
        assert!(
            ProfileContracts {
                private_data: false
            }
            .supported(ev_userspace_contract::app_data::INTERFACE, 1)
            .is_none()
        );
        assert!(
            ProfileContracts { private_data: true }
                .supported(ev_userspace_contract::app_data::INTERFACE, 2)
                .is_none()
        );
        project.profile = "workspace-selected-file-app@1".into();
        project.max_file_bytes = 256;
        project.selection = "exact owner-selected route only".into();
        project.validate().unwrap();
        assert_eq!(project_contracts(&project), contracts());
        assert_eq!(project_caps(&project), caps());
    }
    #[test]
    fn canonical_private_package_requires_exact_nd_file21_and_permission_declarations() {
        let project = private_project();
        let requirements = project_contracts(&project);
        let permissions = project_caps(&project);
        assert!(verify_bytes(&profile_fixture(&project, &requirements, &permissions)).is_ok());
        for mutation in 0..5 {
            let mut contracts = requirements.clone();
            let mut caps = permissions.clone();
            match mutation {
                0 => {
                    contracts.remove(0);
                }
                1 => {
                    let file = contracts
                        .iter_mut()
                        .find(|r| r.name == "ev.internal.file")
                        .unwrap();
                    file.minimum_minor = 0;
                    file.features = 0;
                }
                2 => {
                    contracts[0].major = 2;
                }
                3 => {
                    caps[0].required = false;
                }
                4 => {
                    caps.push(CapabilityRequest {
                        capability: Capability::SelectedFileEdit,
                        required: false,
                    });
                }
                _ => unreachable!(),
            };
            assert!(
                verify_bytes(&profile_fixture(&project, &contracts, &caps)).is_err(),
                "mutation {mutation}"
            );
        }
        let mut project = project;
        project.max_file_bytes = 256;
        assert!(project.validate().is_err());
        project.max_file_bytes = 0;
        project.selection = "exact owner-selected route only".into();
        assert!(project.validate().is_err());
    }
    #[test]
    fn metadata_cannot_select_namespace_or_builtin_identity() {
        let mut p = Project {
            schema: 1,
            name: "Example".into(),
            app_id: "ev.example.file-probe".into(),
            version: [0, 1, 0],
            maturity: "Internal".into(),
            profile: "workspace-selected-file-app@1".into(),
            entry: "file-probe".into(),
            max_file_bytes: 256,
            selection: "exact owner-selected route only".into(),
            data: "private scratch".into(),
            build_scope: "public".into(),
            qualification: "unqualified".into(),
        };
        p.validate().unwrap();
        let first = p.id();
        p.app_id = "ev.example.other".into();
        assert_ne!(first, p.id());
        p.app_id = "evrosion.internal.application.editor".into();
        assert!(p.validate().is_err());
        p.app_id = "ev.example.file-probe".into();
        p.profile = "workspace-namespace-admin@1".into();
        assert!(p.validate().is_err());
        p.profile = LARGE_PROFILE.into();
        assert!(p.validate().is_err()); // the256-byte probe is not widened
        p.max_file_bytes = 1_048_576;
        p.validate().unwrap();
        p.profile = "workspace-selected-file-app@1".into();
        assert!(p.validate().is_err());
    }
}
