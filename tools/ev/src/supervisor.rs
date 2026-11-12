//! Pinned source-built development bundle. Production generation authentication
//! remains separate; these measurements are compiled into the matching kernel.
use crate::{
    build::{self, Artifact},
    toolchain::Toolchain,
};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};
const GENERATION_POLICY: [u64; 4] = [2048, 32, 1, 1];
const OWNER_POLICY: [u64; 4] = [65536, 32, 1, 1];

fn manifest(image: &[u8], graph: bool) -> Vec<u8> {
    let grants: &[(u8, u16)] = if graph {
        &[(1, 1), (2, 8), (5, 256), (1, 1)]
    } else {
        &[(1, 1), (2, 8)]
    };
    manifest_profile(image, grants, 0, [1000, 64, 4, 8], 3, 60)
}

fn custody_manifest(image: &[u8]) -> Vec<u8> {
    manifest_profile(
        image,
        &[(1, 1), (2, 8), (5, 256), (1, 1)],
        0,
        [1000, 64, 4, 8],
        3,
        4096,
    )
}

/// Production selection is shared with the policy tests; a new profile cannot
/// accidentally use an ordinary manifest just because its name lacks a prefix.
fn selected_manifest(image: &[u8], name: &str) -> Vec<u8> {
    let mut bytes = if matches!(
        name,
        "generation-good" | "generation-bad" | "generation-silent"
    ) {
        manifest_profile(image, &[(1, 1), (2, 8)], 0, GENERATION_POLICY, 3, 60)
    } else if matches!(name, "custody-graph" | "custody-exit" | "custody-watchdog") {
        custody_manifest(image)
    } else {
        manifest(image, name.starts_with("graph"))
    };
    if name == "graph-restart" {
        // Preserve accumulated child CPU in this finite declared stress Job.
        // Ordinary Root limits remain unchanged.
        let ticks = ev_kernel::service::RESTART_SERVICE_LIMITS
            .limit(ev_kernel::scheduler::Resource::CpuTicks);
        bytes[80..88].copy_from_slice(&ticks.to_le_bytes());
    }
    bytes
}

fn recovery_manifest(image: &[u8]) -> Vec<u8> {
    // These are distinct permanent roots allocated before any managed graph.
    // The failed Root's ordinary object/lineage identities 0..3 are not reused.
    manifest_profile(image, &[(1, 1), (2, 8)], 4, [64, 16, 1, 1], 0, 1)
}

struct CustodyIntegrityFixtures {
    corrupt_manifest: Vec<u8>,
    corrupt_image: Vec<u8>,
    wrong_authority_manifest: Vec<u8>,
    wrong_authority_measurement: [u8; 32],
}

fn custody_integrity_fixtures(image: &[u8], manifest: &[u8]) -> CustodyIntegrityFixtures {
    // Mutations happen in the host producer; the kernel borrows immutable fixture
    // bytes and never copies a whole ELF onto its bounded boot stack.
    let mut corrupt_manifest = manifest.to_vec();
    corrupt_manifest[0] ^= 1;
    let mut corrupt_image = image.to_vec();
    corrupt_image[0] ^= 1;
    let mut wrong_authority_manifest = manifest.to_vec();
    wrong_authority_manifest[128] ^= 1;
    let wrong_authority_measurement = Sha256::digest(&wrong_authority_manifest).into();
    CustodyIntegrityFixtures {
        corrupt_manifest,
        corrupt_image,
        wrong_authority_manifest,
        wrong_authority_measurement,
    }
}

fn produce_custody_integrity(
    root: &Path,
    directory: &Path,
    image: &[u8],
    manifest: &[u8],
    artifacts: &mut Vec<Artifact>,
    generated: &mut String,
) -> Result<(), String> {
    let fixtures = custody_integrity_fixtures(image, manifest);
    for (file, constant, bytes) in [
        (
            "supervisor-custody-corrupt-manifest.bin",
            "CUSTODY_CORRUPT_MANIFEST",
            &fixtures.corrupt_manifest,
        ),
        (
            "supervisor-custody-corrupt-image.elf",
            "CUSTODY_CORRUPT_IMAGE",
            &fixtures.corrupt_image,
        ),
        (
            "supervisor-custody-wrong-authority.bin",
            "CUSTODY_WRONG_AUTHORITY_MANIFEST",
            &fixtures.wrong_authority_manifest,
        ),
    ] {
        let path = directory.join(file);
        fs::write(&path, bytes).map_err(|e| e.to_string())?;
        *generated += &format!(
            "pub const {constant}: &[u8] = include_bytes!({});\n",
            serde_json::to_string(&path).map_err(|e| e.to_string())?
        );
        artifacts.push(Artifact {
            path: path
                .strip_prefix(root.join("build/m0"))
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("non-UTF-8 custody integrity fixture path")?
                .into(),
            sha256: build::hash_file(&path)?,
        });
    }
    *generated += &format!(
        "pub const CUSTODY_WRONG_AUTHORITY_MEASUREMENT: [u8;32] = {:?};\n",
        fixtures.wrong_authority_measurement
    );
    Ok(())
}

fn manifest_profile(
    image: &[u8],
    grants: &[(u8, u16)],
    first_object: usize,
    limits: [u64; 4],
    attempts: u8,
    window: u64,
) -> Vec<u8> {
    let mut bytes = vec![0u8; 168 + grants.len() * 32];
    bytes[..8].copy_from_slice(b"EVBM0001");
    let put = |b: &mut [u8], i: usize, n: u64| b[i..i + 8].copy_from_slice(&n.to_le_bytes());
    put(&mut bytes, 8, 100);
    bytes[16..48].copy_from_slice(&Sha256::digest(image));
    bytes[48..80].copy_from_slice(&ev_userspace_contract::ABI);
    for (i, n) in limits.into_iter().enumerate() {
        put(&mut bytes, 80 + i * 8, n);
    }
    bytes[112] = attempts;
    put(&mut bytes, 120, window);
    let mut hash = Sha256::new();
    hash.update(b"evrosion.bootstrap.authority.v1\0");
    hash.update((grants.len() as u64).to_le_bytes());
    for (i, &(kind, rights)) in grants.iter().enumerate() {
        hash.update((i as u64 + 1).to_le_bytes());
        hash.update([kind]);
        hash.update(((first_object + i) as u64).to_le_bytes());
        hash.update(((first_object + i) as u64).to_le_bytes());
        hash.update(rights.to_le_bytes());
        hash.update([0]);
        hash.update(0u64.to_le_bytes());
        hash.update(0u64.to_le_bytes());
        let b = &mut bytes[168 + i * 32..168 + (i + 1) * 32];
        put(b, 0, i as u64 + 1);
        b[8] = kind;
        b[10..12].copy_from_slice(&rights.to_le_bytes());
    }
    bytes[128..160].copy_from_slice(&hash.finalize());
    bytes[160] = grants.len() as u8;
    bytes
}

pub(crate) fn produce(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    build_id: &str,
) -> Result<(Vec<Artifact>, std::path::PathBuf), String> {
    let mut artifacts = Vec::new();
    let mut generated =
        String::from("// Source-built, measured Internal development supervisor bundle.\n");
    for (name, features) in [
        ("normal", "executable"),
        ("fault", "test-fault"),
        ("generation-good", "generation-good"),
        ("generation-bad", "generation-bad"),
        ("generation-silent", "generation-silent"),
        ("graph", "service-launch"),
        ("graph-fault", "service-fault"),
        ("graph-rpc", "service-rpc"),
        ("graph-rpc-timeout", "service-rpc-timeout"),
        ("graph-restart", "service-restart"),
        ("custody-graph", "custody-graph"),
        ("custody-exit", "custody-exit"),
        ("custody-watchdog", "custody-watchdog"),
    ] {
        let target = root.join(format!("target/supervisor-{name}"));
        let mut command = Command::new("rustup");
        command.current_dir(root).args(["run",&toolchain.channel,"cargo","build","--locked","--offline",
            "-p","ev-root-supervisor","--release","--features",features,"--target","x86_64-unknown-none","--target-dir"]).arg(&target)
            .env("CARGO_ENCODED_RUSTFLAGS",format!("-C\x1frelocation-model=static\x1f-C\x1fcode-model=large\x1f-C\x1fforce-frame-pointers=yes\x1f-C\x1fdebuginfo=1\x1f-C\x1flink-arg=--no-pie\x1f--remap-path-prefix={}=/evrosion",root.display()))
            .env("RUSTUP_AUTO_INSTALL","0").env("CARGO_TERM_COLOR","never");
        build::logged(
            &mut command,
            &directory.join(format!("supervisor-{name}-build.log")),
        )?;
        let image_path = directory.join(format!("supervisor-{name}.elf"));
        fs::copy(
            target.join("x86_64-unknown-none/release/ev-root-supervisor"),
            &image_path,
        )
        .map_err(|e| e.to_string())?;
        let image = fs::read(&image_path).map_err(|e| e.to_string())?;
        let bytes = selected_manifest(&image, name);
        let measurement: [u8; 32] = Sha256::digest(&bytes).into();
        let verified = ev_kernel::bootstrap_manifest::verify(
            &bytes,
            measurement,
            &image,
            ev_userspace_contract::ABI,
        )
        .map_err(|e| format!("supervisor {name} manifest: {e:?}"))?;
        let plan = ev_kernel::executable::Image::from_manifest(&verified)
            .map_err(|e| format!("supervisor {name} ELF: {e:?}"))?;
        if plan.bootstrap_page().is_none() {
            return Err("supervisor ABI has no startup page".into());
        }
        let manifest_path = directory.join(format!("supervisor-{name}.bin"));
        fs::write(&manifest_path, &bytes).map_err(|e| e.to_string())?;
        let upper = name.to_uppercase().replace('-', "_");
        if name.starts_with("generation-") {
            let feature = if name == "generation-silent" {
                "test-m3-progress"
            } else {
                "test-m3-generation"
            };
            generated += &format!(
                "#[cfg(feature=\"{feature}\")]pub const {upper}_IMAGE:&[u8]=include_bytes!({});\n",
                serde_json::to_string(&image_path).map_err(|e| e.to_string())?
            );
        } else {
            generated += &format!(
                "pub const {upper}_IMAGE: &[u8] = include_bytes!({});\npub const {upper}_MANIFEST: &[u8] = include_bytes!({});\npub const {upper}_MEASUREMENT: [u8;32] = {measurement:?};\n",
                serde_json::to_string(&image_path).map_err(|e| e.to_string())?,
                serde_json::to_string(&manifest_path).map_err(|e| e.to_string())?
            );
        }
        if name == "custody-graph" {
            produce_custody_integrity(
                root,
                directory,
                &image,
                &bytes,
                &mut artifacts,
                &mut generated,
            )?;
        }
        for path in [image_path, manifest_path] {
            artifacts.push(Artifact {
                path: path
                    .strip_prefix(root.join("build/m0"))
                    .map_err(|e| e.to_string())?
                    .to_str()
                    .ok_or("non-UTF-8 bundle path")?
                    .into(),
                sha256: build::hash_file(&path)?,
            });
        }
    }
    produce_recovery(root, directory, toolchain, &mut artifacts, &mut generated)?;
    for (name, features, upper) in [
        ("normal", "executable", "ECHO"),
        ("fault", "test-fault", "ECHO_FAULT"),
        ("delay", "test-delay", "ECHO_DELAY"),
        ("selective", "test-selective-fault", "ECHO_SELECTIVE"),
    ] {
        let target = root.join(format!("target/echo-{name}"));
        let mut command = Command::new("rustup");
        command.current_dir(root).args(["run",&toolchain.channel,"cargo","build","--locked","--offline","-p","ev-echo-service","--release","--features",features,"--target","x86_64-unknown-none","--target-dir"]).arg(&target)
        .env("CARGO_ENCODED_RUSTFLAGS",format!("-C\x1frelocation-model=static\x1f-C\x1fcode-model=large\x1f-C\x1fforce-frame-pointers=yes\x1f-C\x1fdebuginfo=1\x1f-C\x1flink-arg=--no-pie\x1f--remap-path-prefix={}=/evrosion",root.display()))
        .env("RUSTUP_AUTO_INSTALL","0").env("CARGO_TERM_COLOR","never");
        build::logged(
            &mut command,
            &directory.join(format!("echo-{name}-build.log")),
        )?;
        let path = directory.join(format!("echo-{name}.elf"));
        fs::copy(
            target.join("x86_64-unknown-none/release/ev-echo-service"),
            &path,
        )
        .map_err(|e| e.to_string())?;
        let image = fs::read(&path).map_err(|e| e.to_string())?;
        let measurement: [u8; 32] = Sha256::digest(&image).into();
        use ev_kernel::{
            capability::{Kind, Rights},
            service::{RESTART_SERVICE_LIMITS, Role, SERVICE_LIMITS, ServiceImage},
        };
        ServiceImage::verify(
            &image,
            measurement,
            if name == "selective" {
                RESTART_SERVICE_LIMITS
            } else {
                SERVICE_LIMITS
            },
            &[
                Role {
                    selector: 3,
                    kind: Kind::Endpoint,
                    rights: Rights::RECEIVE | Rights::CONTROL,
                },
                Role {
                    selector: 4,
                    kind: Kind::Endpoint,
                    rights: Rights::SEND,
                },
            ],
        )
        .map_err(|e| format!("Echo service image: {e:?}"))?;
        generated += &format!(
            "pub const {upper}_IMAGE:&[u8]=include_bytes!({});\npub const {upper}_SHA:[u8;32]={measurement:?};\n",
            serde_json::to_string(&path).map_err(|e| e.to_string())?
        );
        artifacts.push(Artifact {
            path: path
                .strip_prefix(root.join("build/m0"))
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("non-UTF-8 echo path")?
                .into(),
            sha256: build::hash_file(&path)?,
        });
    }
    produce_cap_actors(root, directory, toolchain, &mut artifacts, &mut generated)?;
    produce_ipc_discipline(root, directory, toolchain, &mut artifacts, &mut generated)?;
    produce_m3_block(root, directory, toolchain, &mut artifacts, &mut generated)?;
    produce_file_actors(root, directory, toolchain, &mut artifacts, &mut generated)?;
    produce_desktop_actors(root, directory, toolchain, &mut artifacts, &mut generated)?;
    produce_generation_catalogue(
        root,
        directory,
        build_id,
        GenerationProfile::Normal,
        &mut artifacts,
        &mut generated,
    )?;
    produce_generation_catalogue(
        root,
        directory,
        build_id,
        GenerationProfile::Owner,
        &mut artifacts,
        &mut generated,
    )?;
    produce_generation_catalogue(
        root,
        directory,
        build_id,
        GenerationProfile::Progress,
        &mut artifacts,
        &mut generated,
    )?;
    let path = directory.join("supervisor-bundle.rs");
    fs::write(&path, generated).map_err(|e| e.to_string())?;
    Ok((artifacts, path))
}

/// The driver receives only one explicitly bound controller, with an attenuated
/// second handle for negative output checks. Application File/Object authority
/// is not replaced by a generic disk-sector or raw-port application interface.
fn m3_block_roles() -> [ev_kernel::service::Role; 2] {
    use ev_kernel::{
        capability::{Kind, Rights},
        service::Role,
    };
    [
        Role {
            selector: 1,
            kind: Kind::IoPorts,
            rights: Rights::READ | Rights::WRITE,
        },
        Role {
            selector: 2,
            kind: Kind::IoPorts,
            rights: Rights::READ,
        },
    ]
}
fn m3_transport_roles(driver: bool) -> Vec<ev_kernel::service::Role> {
    use ev_kernel::{
        capability::{Kind, Rights},
        service::Role,
    };
    if driver {
        vec![
            Role {
                selector: 1,
                kind: Kind::IoPorts,
                rights: Rights::READ | Rights::WRITE,
            },
            Role {
                selector: 2,
                kind: Kind::Memory,
                rights: Rights::READ | Rights::WRITE | Rights::MAP,
            },
            Role {
                selector: 3,
                kind: Kind::Endpoint,
                rights: Rights::RECEIVE | Rights::CONTROL,
            },
        ]
    } else {
        vec![
            Role {
                selector: 1,
                kind: Kind::Memory,
                rights: Rights::READ | Rights::WRITE | Rights::MAP,
            },
            Role {
                selector: 2,
                kind: Kind::Endpoint,
                rights: Rights::SEND,
            },
        ]
    }
}
fn generation_roles() -> Vec<ev_kernel::service::Role> {
    use ev_kernel::{
        capability::{Kind, Rights},
        service::Role,
    };
    [
        (Kind::Memory, 231),
        (Kind::Endpoint, 8),
        (Kind::Job, 256),
        (Kind::Memory, 1),
        (Kind::Memory, 1),
        (Kind::Endpoint, 272),
        (Kind::Endpoint, 232),
        (Kind::Memory, 5),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (kind, bits))| Role {
        selector: index as u64 + 1,
        kind,
        rights: Rights::from_bits(bits).unwrap(),
    })
    .collect()
}
fn owner_roles() -> Vec<ev_kernel::service::Role> {
    use ev_kernel::{
        capability::{Kind, Rights},
        service::Role,
    };
    [
        (Kind::Memory, 231),
        (Kind::Endpoint, 8),
        (Kind::Job, 256),
        (Kind::Memory, 1),
        (Kind::Memory, 1),
        (Kind::Endpoint, 504),
        (Kind::IoPorts, 3),
        (Kind::Memory, 5),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (kind, bits))| Role {
        selector: i as u64 + 1,
        kind,
        rights: Rights::from_bits(bits).unwrap(),
    })
    .collect()
}
fn produce_m3_block(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    artifacts: &mut Vec<Artifact>,
    generated: &mut String,
) -> Result<(), String> {
    use ev_kernel::{scheduler::Limits, service::ServiceImage};
    for (name, feature, upper, roles) in [
        (
            "m3-pio-write",
            "test-write",
            "M3_PIO_WRITE",
            m3_block_roles().to_vec(),
        ),
        (
            "m3-pio-verify",
            "test-verify",
            "M3_PIO_VERIFY",
            m3_block_roles().to_vec(),
        ),
        (
            "m3-pio-direct",
            "test-direct-fault",
            "M3_PIO_DIRECT",
            m3_block_roles().to_vec(),
        ),
        (
            "m3-block-driver",
            "test-block-driver",
            "M3_BLOCK_DRIVER",
            m3_transport_roles(true),
        ),
        (
            "m3-block-client-write",
            "test-block-client-write",
            "M3_BLOCK_CLIENT_WRITE",
            m3_transport_roles(false),
        ),
        (
            "m3-block-client-verify",
            "test-block-client-verify",
            "M3_BLOCK_CLIENT_VERIFY",
            m3_transport_roles(false),
        ),
        (
            "m3-store-client",
            "test-store-client",
            "M3_STORE_CLIENT",
            m3_transport_roles(false),
        ),
        (
            "m3-generation-client",
            "test-generation-client",
            "M3_GENERATION_CLIENT",
            generation_roles(),
        ),
        (
            "m3-owner-client",
            "test-owner-client",
            "M3_OWNER_CLIENT",
            owner_roles(),
        ),
        (
            "m3-progress-client",
            "test-generation-client",
            "M3_PROGRESS_CLIENT",
            generation_roles(),
        ),
    ] {
        let target = root.join(format!("target/{name}"));
        let mut command = Command::new("rustup");
        let mut flags = format!(
            "-C\x1frelocation-model=static\x1f-C\x1fcode-model=large\x1f-C\x1fforce-frame-pointers=yes\x1f-C\x1fdebuginfo=1\x1f-C\x1flink-arg=--no-pie\x1f--remap-path-prefix={}=/evrosion",
            root.display()
        );
        if matches!(
            feature,
            "test-store-client" | "test-generation-client" | "test-owner-client"
        ) {
            // Keep the frozen1MiB measured ELF bound. The Store monomorphized
            // debug sections exceed it; strip only those, retaining symbols and
            // every loaded instruction/data/declared private-stack page.
            flags.push_str("\x1f-C\x1fstrip=debuginfo");
        }
        command
            .current_dir(root)
            .args([
                "run",
                &toolchain.channel,
                "cargo",
                "build",
                "--locked",
                "--offline",
                "-p",
                "ev-block-service",
                "--release",
                "--features",
                feature,
                "--target",
                "x86_64-unknown-none",
                "--target-dir",
            ])
            .arg(&target)
            .env("CARGO_ENCODED_RUSTFLAGS", flags)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .env("CARGO_TERM_COLOR", "never");
        build::logged(&mut command, &directory.join(format!("{name}-build.log")))?;
        let path = directory.join(format!("{name}.elf"));
        fs::copy(
            target.join("x86_64-unknown-none/release/ev-block-service"),
            &path,
        )
        .map_err(|e| e.to_string())?;
        if feature == "test-block-driver" {
            // Retain debugging information separately. SDK debug metadata can
            // exceed the unchanged measured1MiB container bound even though
            // the actual loadable driver is only a few pages.
            let raw_path = directory.join(format!("{name}.unstripped.elf"));
            fs::rename(&path, &raw_path).map_err(|e| e.to_string())?;
            let before = load_identity(&fs::read(&raw_path).map_err(|e| e.to_string())?)?;
            let tool = desktop_tool(root, directory, toolchain)?;
            let strip_log = directory.join(format!("{name}-strip.log"));
            let mut strip = Command::new(&tool);
            strip
                .current_dir(root)
                .arg("--strip-debug")
                .arg(&raw_path)
                .arg(&path);
            build::logged(&mut strip, &strip_log)?;
            let after = load_identity(&fs::read(&path).map_err(|e| e.to_string())?)?;
            if before != after {
                return Err(format!(
                    "PIO driver {name}: stripping changed loaded identity"
                ));
            }
            desktop_graph::retain(root, &raw_path, artifacts)?;
            desktop_graph::retain(root, &strip_log, artifacts)?;
            let record = directory.join(format!("{name}-admission.json"));
            build::write_json(
                &record,
                &serde_json::json!({"schema":1,"kind":"source-driver-debug-separation","unstripped_sha256":build::hash_file(&raw_path)?,"admitted_sha256":build::hash_file(&path)?,"unstripped_bytes":fs::metadata(&raw_path).map_err(|e|e.to_string())?.len(),"admitted_bytes":fs::metadata(&path).map_err(|e|e.to_string())?.len(),"loaded_identity_unchanged":true,"llvm_objcopy":tool,"llvm_objcopy_sha256":build::hash_file(&tool)?,"scope":"Exact entry/PT_LOAD permissions, bytes, zero-fill and alignment comparison only; ordinary ServiceImage admission still required"}),
            )?;
            desktop_graph::retain(root, &record, artifacts)?;
        }
        let image = fs::read(&path).map_err(|e| e.to_string())?;
        let measurement: [u8; 32] = Sha256::digest(&image).into();
        let limits = if feature == "test-owner-client" {
            Limits::new(65536, 32, 1, 1)
        } else if feature == "test-generation-client" {
            Limits::new(2048, 32, 1, 1)
        } else {
            Limits::new(1024, 32, 1, 1)
        };
        let descriptor = ServiceImage::verify(&image, measurement, limits, &roles)
            .map_err(|e| format!("PIO driver {name}: {e:?}"))?;
        if feature == "test-block-driver" {
            // The same measured driver bytes serve both closed profiles. The
            // larger generation workload has an explicit coherent CPU policy;
            // its descriptor is independently admitted without changing legacy.
            ServiceImage::verify(&image, measurement, Limits::new(2048, 32, 1, 1), &roles)
                .map_err(|e| format!("Generation driver {name}: {e:?}"))?;
            ServiceImage::verify(&image, measurement, Limits::new(65536, 32, 1, 1), &roles)
                .map_err(|e| format!("Owner driver {name}: {e:?}"))?;
        }
        if matches!(
            feature,
            "test-store-client" | "test-generation-client" | "test-owner-client"
        ) {
            verify_store_stack(&descriptor)?;
        }
        let cfg = if name == "m3-progress-client" {
            "feature=\"test-m3-progress\""
        } else if feature == "test-owner-client" {
            "feature=\"test-m3-owner\""
        } else if feature == "test-generation-client" {
            "feature=\"test-m3-generation\""
        } else if feature == "test-store-client" {
            "feature=\"test-m3-store\""
        } else {
            "any(feature=\"test-m3-pio-write\",feature=\"test-m3-pio-verify\")"
        };
        *generated += &format!(
            "#[cfg({cfg})]\npub const {upper}_IMAGE:&[u8]=include_bytes!({});\n#[cfg({cfg})]\npub const {upper}_SHA:[u8;32]={measurement:?};\n",
            serde_json::to_string(&path).map_err(|e| e.to_string())?
        );
        artifacts.push(Artifact {
            path: path
                .strip_prefix(root.join("build/m0"))
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("non-UTF-8 PIO driver image path")?
                .into(),
            sha256: build::hash_file(&path)?,
        });
    }
    Ok(())
}
#[derive(Clone, Copy)]
enum GenerationProfile {
    Normal,
    Owner,
    Progress,
}
impl GenerationProfile {
    fn settings(
        self,
    ) -> (
        &'static str,
        &'static str,
        &'static str,
        [u64; 4],
        &'static str,
    ) {
        match self {
            Self::Normal => (
                "m3-generation",
                "M3_GENERATION",
                "test-m3-generation",
                GENERATION_POLICY,
                "supervisor-generation-bad.elf",
            ),
            Self::Owner => (
                "m3-owner",
                "M3_OWNER",
                "test-m3-owner",
                OWNER_POLICY,
                "supervisor-generation-bad.elf",
            ),
            Self::Progress => (
                "m3-progress",
                "M3_PROGRESS",
                "test-m3-progress",
                GENERATION_POLICY,
                "supervisor-generation-silent.elf",
            ),
        }
    }
}
fn produce_generation_catalogue(
    root: &Path,
    directory: &Path,
    build_id: &str,
    profile: GenerationProfile,
    artifacts: &mut Vec<Artifact>,
    generated: &mut String,
) -> Result<(), String> {
    use ev_userspace_contract::generation::{Catalogue, HEALTH_DESCRIPTION, Slot};
    if build_id.len() != 64 || !build_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("generation catalogue requires exact build-input identity".into());
    }
    let mut kernel_build = [0u8; 32];
    for (i, byte) in kernel_build.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&build_id[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    let image_hash = |name: &str| -> Result<[u8; 32], String> {
        Ok(Sha256::digest(fs::read(directory.join(name)).map_err(|e| e.to_string())?).into())
    };
    let (stem, upper, feature, policy, image_b) = profile.settings();
    let catalogue = Catalogue {
        kernel_build,
        controller: image_hash(&format!("{stem}-client.elf"))?,
        driver: image_hash("m3-block-driver.elf")?,
        image_a: image_hash("supervisor-generation-good.elf")?,
        image_b: image_hash(image_b)?,
        abi: ev_userspace_contract::ABI,
        health: Sha256::digest(HEALTH_DESCRIPTION).into(),
        health_version: 1,
        required_checks: 3,
    };
    let bytes = catalogue.encode();
    let roles = [
        ev_kernel::service::Role {
            selector: 1,
            kind: ev_kernel::capability::Kind::Memory,
            rights: ev_kernel::capability::Rights::READ,
        },
        ev_kernel::service::Role {
            selector: 2,
            kind: ev_kernel::capability::Kind::Endpoint,
            rights: ev_kernel::capability::Rights::SEND,
        },
    ];
    for (name, expected) in [
        ("supervisor-generation-good.elf", catalogue.image_a),
        (image_b, catalogue.image_b),
    ] {
        let image = fs::read(directory.join(name)).map_err(|e| e.to_string())?;
        ev_kernel::service::ServiceImage::verify(
            &image,
            expected,
            ev_kernel::scheduler::Limits::new(policy[0], policy[1], policy[2], policy[3]),
            &roles,
        )
        .map_err(|e| format!("{stem} critical descriptor: {e:?}"))?;
    }
    Catalogue::decode(&bytes).map_err(|e| format!("generation catalogue: {e:?}"))?;
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    let path = directory.join(format!("{stem}-catalogue.bin"));
    fs::write(&path, bytes).map_err(|e| e.to_string())?;
    *generated += &format!(
        "#[cfg(feature=\"{feature}\")]pub const {upper}_CATALOGUE:&[u8]=include_bytes!({});\n#[cfg(feature=\"{feature}\")]pub const {upper}_CATALOGUE_SHA:[u8;32]={hash:?};\n",
        serde_json::to_string(&path).map_err(|e| e.to_string())?
    );
    let description = directory.join(format!("{stem}-catalogue.json"));
    build::write_json(
        &description,
        &serde_json::json!({"schema":1,"kernel_identity":"build input ID; exact binary hashes retained in build manifest","kernel_build_input":build_id,"controller":catalogue.controller,"driver":catalogue.driver,"image_a":catalogue.image_a,"image_b":catalogue.image_b,"abi":catalogue.abi,"health_contract":catalogue.health,"health_version":1,"required_checks":3,"cohort_a":<[u8;32]>::from(Sha256::digest(catalogue.cohort_input(Slot::A))),"cohort_b":<[u8;32]>::from(Sha256::digest(catalogue.cohort_input(Slot::B))),"generation_limits":{"controller":policy,"driver":policy,"critical":policy},"legacy_driver_limits":[1024,32,1,1],"publisher_authenticated":false}),
    )?;
    for path in [path, description] {
        artifacts.push(Artifact {
            path: path
                .strip_prefix(root.join("build/m0"))
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("nonUTF8generation catalogue path")?
                .into(),
            sha256: build::hash_file(&path)?,
        });
    }
    Ok(())
}
fn produce_file_actors(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    artifacts: &mut Vec<Artifact>,
    generated: &mut String,
) -> Result<(), String> {
    use ev_kernel::{
        capability::{Kind, Rights},
        scheduler::Limits,
        service::{Role, ServiceImage},
    };
    for (feature, upper) in [("server", "M3_FILE_SERVER"), ("app", "M3_FILE_APP")] {
        let name = format!("m3-file-{feature}");
        let target = root.join(format!("target/{name}"));
        let mut command = Command::new("rustup");
        command.current_dir(root).args(["run",&toolchain.channel,"cargo","build","--locked","--offline","-p","ev-file-service","--bin","ev-file-service","--release","--features",feature,"--target","x86_64-unknown-none","--target-dir"]).arg(&target)
            .env("CARGO_ENCODED_RUSTFLAGS",format!("-C\x1frelocation-model=static\x1f-C\x1fcode-model=large\x1f-C\x1fforce-frame-pointers=yes\x1f-C\x1fdebuginfo=1\x1f-C\x1flink-arg=--no-pie\x1f-C\x1fstrip=debuginfo\x1f--remap-path-prefix={}=/evrosion",root.display()))
            .env("RUSTUP_AUTO_INSTALL","0").env("CARGO_TERM_COLOR","never");
        build::logged(&mut command, &directory.join(format!("{name}-build.log")))?;
        let path = directory.join(format!("{name}.elf"));
        fs::copy(
            target.join("x86_64-unknown-none/release/ev-file-service"),
            &path,
        )
        .map_err(|e| e.to_string())?;
        let image = fs::read(&path).map_err(|e| e.to_string())?;
        let sha: [u8; 32] = Sha256::digest(&image).into();
        let shape: &[(Kind, u16)] = if feature == "server" {
            &[
                (Kind::Memory, 7),
                (Kind::Endpoint, 8),
                (Kind::Memory, 7),
                (Kind::Endpoint, 272),
                (Kind::Endpoint, 272),
            ]
        } else {
            &[(Kind::Memory, 7), (Kind::Endpoint, 8), (Kind::Endpoint, 8)]
        };
        let roles: Vec<_> = shape
            .iter()
            .enumerate()
            .map(|(i, (kind, bits))| Role {
                selector: i as u64 + 1,
                kind: *kind,
                rights: Rights::from_bits(*bits).unwrap(),
            })
            .collect();
        let descriptor = ServiceImage::verify(&image, sha, Limits::new(2048, 32, 1, 1), &roles)
            .map_err(|e| format!("File {feature} admission: {e:?}"))?;
        verify_store_stack(&descriptor)?;
        *generated += &format!(
            "#[cfg(feature=\"test-m3-file\")]pub const {upper}_IMAGE:&[u8]=include_bytes!({});\n#[cfg(feature=\"test-m3-file\")]pub const {upper}_SHA:[u8;32]={sha:?};\n",
            serde_json::to_string(&path).map_err(|e| e.to_string())?
        );
        artifacts.push(Artifact {
            path: path
                .strip_prefix(root.join("build/m0"))
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("nonUTF8Fileimagepath")?
                .into(),
            sha256: build::hash_file(&path)?,
        });
    }
    Ok(())
}

fn desktop_roles(display: bool) -> Vec<ev_kernel::service::Role> {
    use ev_kernel::{
        capability::{Kind, Rights},
        service::Role,
    };
    let shape: &[(Kind, u16)] = if display {
        &[
            (Kind::Memory, 5),
            (Kind::Endpoint, 272),
            (Kind::Display, 7),
            (Kind::Endpoint, 8),
        ]
    } else {
        &[(Kind::Memory, 7), (Kind::Endpoint, 8), (Kind::Endpoint, 8)]
    };
    shape
        .iter()
        .enumerate()
        .map(|(i, (kind, bits))| Role {
            selector: i as u64 + 1,
            kind: *kind,
            rights: Rights::from_bits(*bits).unwrap(),
        })
        .collect()
}

fn desktop_descriptor(
    bytes: &[u8],
    display: bool,
) -> Result<ev_kernel::service::ServiceImage<'_>, String> {
    use ev_kernel::{executable::LayoutReservation, scheduler::Limits, service::ServiceImage};
    ServiceImage::verify_layout(
        bytes,
        Sha256::digest(bytes).into(),
        Limits::new(2048, 32, 1, 1),
        &desktop_roles(display),
        if display {
            LayoutReservation::DisplayApertureV1
        } else {
            LayoutReservation::Legacy
        },
    )
    .map_err(|error| format!("desktop measured descriptor: {error:?}"))
}

#[derive(Debug, PartialEq, Eq)]
struct LoadIdentity {
    entry: u64,
    segments: Vec<LoadSegmentIdentity>,
}
#[derive(Debug, PartialEq, Eq)]
struct LoadSegmentIdentity {
    flags: u32,
    address: u64,
    physical: u64,
    memory_bytes: u64,
    alignment: u64,
    initialized: Vec<u8>,
}
/// Debug stripping may rewrite section metadata/file offsets, never a loaded
/// byte, entry point, segment permission, zero-fill extent or alignment.
fn load_identity(bytes: &[u8]) -> Result<LoadIdentity, String> {
    let read = |offset: usize, count: usize| bytes.get(offset..offset.checked_add(count)?);
    let half = |offset| -> Result<u16, String> {
        Ok(u16::from_le_bytes(
            read(offset, 2)
                .ok_or("truncated ELF field")?
                .try_into()
                .map_err(|_| "ELF half")?,
        ))
    };
    let word = |offset| -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            read(offset, 4)
                .ok_or("truncated ELF field")?
                .try_into()
                .map_err(|_| "ELF word")?,
        ))
    };
    let wide = |offset| -> Result<u64, String> {
        Ok(u64::from_le_bytes(
            read(offset, 8)
                .ok_or("truncated ELF field")?
                .try_into()
                .map_err(|_| "ELF wide")?,
        ))
    };
    if bytes.len() < 64
        || read(0, 7) != Some(b"\x7fELF\x02\x01\x01".as_slice())
        || half(16)? != 2
        || half(18)? != 62
        || half(52)? != 64
        || half(54)? != 56
    {
        return Err("unsupported ELF load identity".into());
    }
    let count = usize::from(half(56)?);
    let start = usize::try_from(wide(32)?).map_err(|_| "ELF header offset")?;
    if !(1..=ev_kernel::executable::MAX_SEGMENTS).contains(&count)
        || read(start, count * 56).is_none()
    {
        return Err("invalid ELF load table".into());
    }
    let mut segments = Vec::new();
    for i in 0..count {
        let header = start + i * 56;
        match word(header)? {
            0 => continue,
            1 => (),
            _ => return Err("unsupported ELF load header".into()),
        };
        let offset = usize::try_from(wide(header + 8)?).map_err(|_| "ELF file offset")?;
        let initialized =
            usize::try_from(wide(header + 32)?).map_err(|_| "ELF initialized length")?;
        let memory_bytes = wide(header + 40)?;
        if memory_bytes < initialized as u64 || memory_bytes == 0 {
            return Err("invalid ELF load extent".into());
        }
        segments.push(LoadSegmentIdentity {
            flags: word(header + 4)?,
            address: wide(header + 16)?,
            physical: wide(header + 24)?,
            memory_bytes,
            alignment: wide(header + 48)?,
            initialized: read(offset, initialized)
                .ok_or("truncated ELF load bytes")?
                .to_vec(),
        });
    }
    if segments.is_empty() {
        return Err("ELF has no load segments".into());
    }
    Ok(LoadIdentity {
        entry: wide(24)?,
        segments,
    })
}

fn desktop_tool(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
) -> Result<std::path::PathBuf, String> {
    let log = directory.join("m4-display-sysroot.log");
    let mut command = Command::new("rustup");
    command
        .current_dir(root)
        .args(["run", &toolchain.channel, "rustc", "--print", "sysroot"])
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("CARGO_TERM_COLOR", "never");
    build::logged(&mut command, &log)?;
    let sysroot = fs::read_to_string(&log).map_err(|e| e.to_string())?;
    let mut found = fs::read_dir(Path::new(sysroot.trim()).join("lib/rustlib"))
        .map_err(|e| e.to_string())?
        .map(|entry| {
            entry
                .map(|entry| entry.path().join("bin/llvm-objcopy"))
                .map_err(|e| e.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|path| path.is_file());
    let tool = found
        .next()
        .ok_or("pinned llvm-tools-preview llvm-objcopy is missing")?;
    if found.next().is_some() {
        return Err("ambiguous pinned llvm-objcopy".into());
    }
    Ok(tool)
}

pub(crate) fn produce_desktop_actors(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    artifacts: &mut Vec<Artifact>,
    generated: &mut String,
) -> Result<(), String> {
    let tool = desktop_tool(root, directory, toolchain)?;
    let mut measurements = Vec::new();
    for (feature, name, upper, display) in [
        ("app", "m4-display-app", "M4_DISPLAY_APP", false),
        ("display", "m4-display-server", "M4_DISPLAY_SERVER", true),
        (
            "app-denied-framebuffer",
            "m4-display-app-denied",
            "M4_DISPLAY_APP_DENIED",
            false,
        ),
        (
            "display-denied-surface",
            "m4-display-server-denied",
            "M4_DISPLAY_SERVER_DENIED",
            true,
        ),
    ] {
        let target = root.join(format!("target/{name}"));
        let mut command = Command::new("rustup");
        command.current_dir(root).args(["run",&toolchain.channel,"cargo","build","--locked","--offline","-p","ev-desktop","--bin","ev-desktop","--release","--features",feature,"--target","x86_64-unknown-none","--target-dir"]).arg(&target)
            .env("CARGO_ENCODED_RUSTFLAGS",format!("-C\x1frelocation-model=static\x1f-C\x1fcode-model=large\x1f-C\x1fforce-frame-pointers=yes\x1f-C\x1fdebuginfo=1\x1f-C\x1flink-arg=--no-pie\x1f--remap-path-prefix={}=/evrosion",root.display()))
            .env("RUSTUP_AUTO_INSTALL","0").env("CARGO_TERM_COLOR","never");
        build::logged(&mut command, &directory.join(format!("{name}-build.log")))?;
        let raw_path = directory.join(format!("{name}.unstripped.elf"));
        fs::copy(
            target.join("x86_64-unknown-none/release/ev-desktop"),
            &raw_path,
        )
        .map_err(|e| e.to_string())?;
        let raw = fs::read(&raw_path).map_err(|e| e.to_string())?;
        let before = load_identity(&raw)?;
        let path = directory.join(format!("{name}.elf"));
        let mut command = Command::new(&tool);
        command
            .current_dir(root)
            .arg("--strip-debug")
            .arg(&raw_path)
            .arg(&path);
        build::logged(&mut command, &directory.join(format!("{name}-strip.log")))?;
        let image = fs::read(&path).map_err(|e| e.to_string())?;
        let after = load_identity(&image)?;
        if before != after {
            return Err(format!("{name}: debug stripping changed loaded identity"));
        }
        let descriptor = desktop_descriptor(&image, display)?;
        verify_store_stack(&descriptor)?;
        let plan = descriptor
            .plan()
            .map_err(|e| format!("desktop plan: {e:?}"))?;
        for page in 383..=447 {
            if plan.pages().any(|p| p.address == plan.base() + page * 4096) {
                return Err(format!(
                    "{name}: private image overlaps surface/guard page{page}"
                ));
            }
        }
        let sha: [u8; 32] = Sha256::digest(&image).into();
        *generated += &format!(
            "#[cfg(feature=\"test-m4-display\")]pub const {upper}_IMAGE:&[u8]=include_bytes!({});\n#[cfg(feature=\"test-m4-display\")]pub const {upper}_SHA:[u8;32]={sha:?};\n",
            serde_json::to_string(&path).map_err(|e| e.to_string())?
        );
        measurements.push(serde_json::json!({"feature":feature,"artifact":format!("{name}.elf"),"image_sha256":format!("{:x}",Sha256::digest(&image)),"raw_sha256":format!("{:x}",Sha256::digest(&raw)),"descriptor_sha256":descriptor.digest(),"layout":if display{"DisplayApertureV1"}else{"Legacy"},"limits":[2048,32,1,1],"load_pages":plan.pages().count(),"private_frames":plan.private_required_frames(),"additional_table_frames":plan.layout().additional_table_frames(),"total_frames":plan.required_frames(),"load_identity_preserved":true,"measured_stack_bytes":16384,"surface_first_page":384,"surface_pages":63,"surface_guards":[383,447]}));
        for path in [raw_path, path] {
            artifacts.push(Artifact {
                path: path
                    .strip_prefix(root.join("build/m0"))
                    .map_err(|e| e.to_string())?
                    .to_str()
                    .ok_or("nonUTF8desktopartifact")?
                    .into(),
                sha256: build::hash_file(&path)?,
            });
        }
    }
    let record = directory.join("m4-display-measurements.json");
    build::write_json(
        &record,
        &serde_json::json!({"schema":1,"kind":"desktop-service-measurements","scope":"ELF/descriptor admission, not actual display execution","llvm_objcopy":tool,"llvm_objcopy_sha256":build::hash_file(&tool)?,"toolchain":toolchain.channel,"images":measurements}),
    )?;
    artifacts.push(Artifact {
        path: record
            .strip_prefix(root.join("build/m0"))
            .map_err(|e| e.to_string())?
            .to_str()
            .ok_or("nonUTF8desktopmeasurement")?
            .into(),
        sha256: build::hash_file(&record)?,
    });
    Ok(())
}
/// Stack backing is part of the immutable measured ELF and its ordinary frame
/// admission. No uncharged stack, mutable global owner or kernel stack increase.
fn verify_store_stack(descriptor: &ev_kernel::service::ServiceImage<'_>) -> Result<(), String> {
    use ev_kernel::user::UserPermission;
    let plan = descriptor
        .plan()
        .map_err(|e| format!("Store load plan: {e:?}"))?;
    let base = plan.base();
    for guard in [0xff000, 0x104000, 507 * 4096, 508 * 4096] {
        if plan.pages().any(|page| page.address == base + guard) {
            return Err(format!("Store stack/shared guard occupied: {guard:#x}"));
        }
    }
    for offset in (0x100000..0x104000).step_by(4096) {
        let page = plan
            .pages()
            .find(|page| page.address == base + offset)
            .ok_or("missing declared Store stack page")?;
        if page.permission != UserPermission::ReadWrite {
            return Err("Store stack must be RW/NX".into());
        }
        let mut bytes = [0; 4096];
        page.copy_into(&mut bytes);
        if bytes.iter().any(|byte| *byte != 0) {
            return Err("Store stack must be entirely zero initialized".into());
        }
    }
    Ok(())
}

fn discipline_roles(depth: bool) -> Vec<ev_kernel::service::Role> {
    use ev_kernel::{
        capability::{Kind, Rights},
        service::Role,
    };
    let mut roles: Vec<Role> = (1..=6)
        .map(|selector| Role {
            selector,
            kind: Kind::Endpoint,
            rights: if selector % 2 == 1 {
                Rights::RECEIVE | Rights::CONTROL
            } else {
                Rights::SEND
            },
        })
        .collect();
    if !depth {
        roles.push(Role {
            selector: 7,
            kind: Kind::Mutex,
            rights: Rights::CONTROL,
        });
    }
    roles
}

fn discipline_stack_layout(plan: &ev_kernel::executable::Image<'_>) -> bool {
    use ev_kernel::user::UserPermission;
    let base = plan.base();
    for offset in [0x100000, 0x102000] {
        let Some(page) = plan.pages().find(|page| page.address == base + offset) else {
            return false;
        };
        if page.permission != UserPermission::ReadWrite {
            return false;
        }
        let mut bytes = [0xff; 4096];
        page.copy_into(&mut bytes);
        if bytes.iter().any(|&byte| byte != 0) {
            return false;
        }
    }
    for offset in [0xff000, 0x101000, 0x103000] {
        if plan.pages().any(|page| page.address == base + offset) {
            return false;
        }
    }
    true
}

fn produce_ipc_discipline(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    artifacts: &mut Vec<Artifact>,
    generated: &mut String,
) -> Result<(), String> {
    use ev_kernel::{scheduler::Limits, service::ServiceImage};
    for (name, features, upper, depth) in [
        ("ipc-chain", "executable", "IPC_CHAIN", false),
        ("ipc-depth", "depth", "IPC_DEPTH", true),
    ] {
        let target = root.join(format!("target/{name}"));
        let mut command = Command::new("rustup");
        command.current_dir(root).args(["run", &toolchain.channel, "cargo", "build", "--locked", "--offline",
            "-p", "ev-ipc-discipline", "--release", "--features", features, "--target", "x86_64-unknown-none", "--target-dir"])
            .arg(&target)
            .env("CARGO_ENCODED_RUSTFLAGS", format!("-C\x1frelocation-model=static\x1f-C\x1fcode-model=large\x1f-C\x1fforce-frame-pointers=yes\x1f-C\x1fdebuginfo=1\x1f-C\x1flink-arg=--no-pie\x1f--remap-path-prefix={}=/evrosion", root.display()))
            .env("RUSTUP_AUTO_INSTALL", "0").env("CARGO_TERM_COLOR", "never");
        build::logged(&mut command, &directory.join(format!("{name}-build.log")))?;
        let path = directory.join(format!("{name}.elf"));
        fs::copy(
            target.join("x86_64-unknown-none/release/ev-ipc-discipline"),
            &path,
        )
        .map_err(|e| e.to_string())?;
        let image = fs::read(&path).map_err(|e| e.to_string())?;
        let measurement: [u8; 32] = Sha256::digest(&image).into();
        let descriptor = ServiceImage::verify(
            &image,
            measurement,
            Limits::new(512, 16, 1, if depth { 3 } else { 1 }),
            &discipline_roles(depth),
        )
        .map_err(|e| format!("discipline actor {name}: {e:?}"))?;
        if !discipline_stack_layout(
            &descriptor
                .plan()
                .map_err(|e| format!("discipline plan: {e:?}"))?,
        ) {
            return Err(format!(
                "{name} is missing its zero private stacks or guard holes"
            ));
        }
        *generated += &format!(
            "pub const {upper}_IMAGE:&[u8]=include_bytes!({});\npub const {upper}_SHA:[u8;32]={measurement:?};\n",
            serde_json::to_string(&path).map_err(|e| e.to_string())?
        );
        artifacts.push(Artifact {
            path: path
                .strip_prefix(root.join("build/m0"))
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("non-UTF-8 discipline image path")?
                .into(),
            sha256: build::hash_file(&path)?,
        });
    }
    Ok(())
}

fn produce_cap_actors(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    artifacts: &mut Vec<Artifact>,
    generated: &mut String,
) -> Result<(), String> {
    use ev_kernel::{
        capability::{Kind, Rights},
        scheduler::Limits,
        service::{Role, ServiceImage},
    };
    let memory = Rights::READ | Rights::TRANSFER;
    let client_roles = [
        Role {
            selector: 1,
            kind: Kind::Memory,
            rights: memory,
        },
        Role {
            selector: 2,
            kind: Kind::Memory,
            rights: memory,
        },
        Role {
            selector: 3,
            kind: Kind::Endpoint,
            rights: Rights::SEND,
        },
        Role {
            selector: 4,
            kind: Kind::Endpoint,
            rights: Rights::RECEIVE | Rights::CONTROL,
        },
    ];
    let server_roles = [
        Role {
            selector: 3,
            kind: Kind::Endpoint,
            rights: Rights::RECEIVE | Rights::CONTROL,
        },
        Role {
            selector: 4,
            kind: Kind::Endpoint,
            rights: Rights::SEND,
        },
    ];
    for (name, package, features, upper, roles) in [
        (
            "cap-client-normal",
            "ev-cap-client",
            "executable",
            "CAP_CLIENT_NORMAL",
            &client_roles[..],
        ),
        (
            "cap-client-timeout",
            "ev-cap-client",
            "test-timeout",
            "CAP_CLIENT_TIMEOUT",
            &client_roles[..],
        ),
        (
            "cap-client-death",
            "ev-cap-client",
            "test-death",
            "CAP_CLIENT_DEATH",
            &client_roles[..],
        ),
        (
            "cap-client-queued-timeout",
            "ev-cap-client",
            "test-queued-timeout",
            "CAP_CLIENT_QUEUED_TIMEOUT",
            &client_roles[..],
        ),
        (
            "cap-client-queued-death",
            "ev-cap-client",
            "test-queued-death",
            "CAP_CLIENT_QUEUED_DEATH",
            &client_roles[..],
        ),
        (
            "cap-server-normal",
            "ev-cap-server",
            "executable",
            "CAP_SERVER_NORMAL",
            &server_roles[..],
        ),
        (
            "cap-server-delay",
            "ev-cap-server",
            "test-delay",
            "CAP_SERVER_DELAY",
            &server_roles[..],
        ),
        (
            "cap-server-fault",
            "ev-cap-server",
            "test-fault",
            "CAP_SERVER_FAULT",
            &server_roles[..],
        ),
        (
            "cap-server-hold",
            "ev-cap-server",
            "test-hold",
            "CAP_SERVER_HOLD",
            &server_roles[..],
        ),
        (
            "cap-server-queued-fault",
            "ev-cap-server",
            "test-queued-fault",
            "CAP_SERVER_QUEUED_FAULT",
            &server_roles[..],
        ),
    ] {
        let target = root.join(format!("target/{name}"));
        let mut command = Command::new("rustup");
        command.current_dir(root).args(["run", &toolchain.channel, "cargo", "build", "--locked", "--offline",
            "-p", package, "--release", "--features", features, "--target", "x86_64-unknown-none", "--target-dir"])
            .arg(&target)
            .env("CARGO_ENCODED_RUSTFLAGS", format!("-C\x1frelocation-model=static\x1f-C\x1fcode-model=large\x1f-C\x1fforce-frame-pointers=yes\x1f-C\x1fdebuginfo=1\x1f-C\x1flink-arg=--no-pie\x1f--remap-path-prefix={}=/evrosion", root.display()))
            .env("RUSTUP_AUTO_INSTALL", "0").env("CARGO_TERM_COLOR", "never");
        build::logged(&mut command, &directory.join(format!("{name}-build.log")))?;
        let path = directory.join(format!("{name}.elf"));
        fs::copy(
            target.join("x86_64-unknown-none/release").join(package),
            &path,
        )
        .map_err(|e| e.to_string())?;
        let image = fs::read(&path).map_err(|e| e.to_string())?;
        let measurement: [u8; 32] = Sha256::digest(&image).into();
        ServiceImage::verify(&image, measurement, Limits::new(512, 16, 1, 1), roles)
            .map_err(|e| format!("cap actor {name} image: {e:?}"))?;
        *generated += &format!(
            "pub const {upper}_IMAGE: &[u8] = include_bytes!({});\npub const {upper}_SHA: [u8;32] = {measurement:?};\n",
            serde_json::to_string(&path).map_err(|e| e.to_string())?
        );
        artifacts.push(Artifact {
            path: path
                .strip_prefix(root.join("build/m0"))
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("non-UTF-8 capability actor path")?
                .into(),
            sha256: build::hash_file(&path)?,
        });
    }
    Ok(())
}

fn produce_recovery(
    root: &Path,
    directory: &Path,
    toolchain: &Toolchain,
    artifacts: &mut Vec<Artifact>,
    generated: &mut String,
) -> Result<(), String> {
    let target = root.join("target/recovery");
    let mut command = Command::new("rustup");
    command.current_dir(root).args(["run", &toolchain.channel, "cargo", "build", "--locked", "--offline",
        "-p", "ev-recovery-service", "--release", "--features", "executable", "--target", "x86_64-unknown-none", "--target-dir"])
        .arg(&target)
        .env("CARGO_ENCODED_RUSTFLAGS", format!("-C\x1frelocation-model=static\x1f-C\x1fcode-model=large\x1f-C\x1fforce-frame-pointers=yes\x1f-C\x1fdebuginfo=1\x1f-C\x1flink-arg=--no-pie\x1f--remap-path-prefix={}=/evrosion", root.display()))
        .env("RUSTUP_AUTO_INSTALL", "0").env("CARGO_TERM_COLOR", "never");
    build::logged(&mut command, &directory.join("recovery-build.log"))?;
    let image_path = directory.join("recovery.elf");
    fs::copy(
        target.join("x86_64-unknown-none/release/ev-recovery-service"),
        &image_path,
    )
    .map_err(|e| e.to_string())?;
    let image = fs::read(&image_path).map_err(|e| e.to_string())?;
    let bytes = recovery_manifest(&image);
    let measurement: [u8; 32] = Sha256::digest(&bytes).into();
    let verified = ev_kernel::bootstrap_manifest::verify(
        &bytes,
        measurement,
        &image,
        ev_userspace_contract::ABI,
    )
    .map_err(|e| format!("recovery manifest: {e:?}"))?;
    let plan = ev_kernel::executable::Image::from_manifest(&verified)
        .map_err(|e| format!("recovery ELF: {e:?}"))?;
    if plan.bootstrap_page().is_none() {
        return Err("recovery ABI has no startup page".into());
    }
    let manifest_path = directory.join("recovery.bin");
    fs::write(&manifest_path, bytes).map_err(|e| e.to_string())?;
    *generated += &format!(
        "pub const RECOVERY_IMAGE: &[u8] = include_bytes!({});\npub const RECOVERY_MANIFEST: &[u8] = include_bytes!({});\npub const RECOVERY_MEASUREMENT: [u8;32] = {measurement:?};\n",
        serde_json::to_string(&image_path).map_err(|e| e.to_string())?,
        serde_json::to_string(&manifest_path).map_err(|e| e.to_string())?
    );
    for path in [image_path, manifest_path] {
        artifacts.push(Artifact {
            path: path
                .strip_prefix(root.join("build/m0"))
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("non-UTF-8 recovery path")?
                .into(),
            sha256: build::hash_file(&path)?,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn desktop_profiles_keep_device_authority_only_in_display_and_measure_extra_tables() {
        use ev_kernel::{capability::Kind, executable::LayoutReservation, scheduler::Resource};
        let app = desktop_roles(false);
        let display = desktop_roles(true);
        assert_eq!(
            app.iter()
                .map(|r| (r.selector, r.kind, r.rights.bits()))
                .collect::<Vec<_>>(),
            [
                (1, Kind::Memory, 7),
                (2, Kind::Endpoint, 8),
                (3, Kind::Endpoint, 8)
            ]
        );
        assert_eq!(
            display
                .iter()
                .map(|r| (r.selector, r.kind, r.rights.bits()))
                .collect::<Vec<_>>(),
            [
                (1, Kind::Memory, 5),
                (2, Kind::Endpoint, 272),
                (3, Kind::Display, 7),
                (4, Kind::Endpoint, 8)
            ]
        );
        let bytes = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let app = desktop_descriptor(bytes, false).unwrap();
        let display = desktop_descriptor(bytes, true).unwrap();
        assert_eq!(app.layout(), LayoutReservation::Legacy);
        assert_eq!(display.layout(), LayoutReservation::DisplayApertureV1);
        assert_eq!(app.plan().unwrap().required_frames(), 10);
        assert_eq!(display.plan().unwrap().required_frames(), 12);
        for descriptor in [app, display] {
            assert_eq!(descriptor.limits().limit(Resource::CpuTicks), 2048);
            assert_eq!(descriptor.limits().limit(Resource::Frames), 32);
        }
    }
    #[test]
    fn debug_strip_identity_ignores_only_unloaded_section_metadata() {
        let bytes = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let identity = load_identity(bytes).unwrap();
        let mut metadata = bytes.to_vec();
        metadata[40..48].copy_from_slice(&1234u64.to_le_bytes());
        // This narrow comparison is NOT ELF admission. The independent final
        // ServiceImage verifier still rejects malformed section metadata.
        assert_eq!(load_identity(&metadata).unwrap(), identity);
        assert!(desktop_descriptor(&metadata, false).is_err());
        for offset in [24, 64 + 4, 64 + 16, 64 + 24, 64 + 40, 64 + 48, 4096] {
            let mut changed = bytes.to_vec();
            changed[offset] ^= 1;
            assert!(
                load_identity(&changed).map_or(true, |changed| changed != identity),
                "offset{offset}"
            );
        }
    }
    #[test]
    fn desktop_load_identity_rejects_truncated_or_overflowed_tables_without_panicking() {
        let bytes = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        for length in 0..64 {
            assert!(load_identity(&bytes[..length]).is_err());
        }
        let mut bad = bytes.to_vec();
        bad[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(load_identity(&bad).is_err());
        bad = bytes.to_vec();
        bad[64 + 8..64 + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(load_identity(&bad).is_err());
        bad = bytes.to_vec();
        bad[64 + 32..64 + 40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(load_identity(&bad).is_err());
        for length in [64, 100, 4096, 8192] {
            assert!(load_identity(&bytes[..length]).is_err());
        }
    }
    #[test]
    fn recovery_measurement_requires_distinct_permanent_roots_and_no_creator_rights() {
        use ev_kernel::{
            bootstrap_binding::{self, CatalogEntry},
            capability::{Authority, Error, Kind, Rights},
            restart::{Budget, RecoveryRequired},
            scheduler::Resource,
        };
        let image = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let bytes = recovery_manifest(image);
        let m = ev_kernel::bootstrap_manifest::verify(
            &bytes,
            Sha256::digest(&bytes).into(),
            image,
            ev_userspace_contract::ABI,
        )
        .unwrap();
        assert_eq!(m.limits().limit(Resource::CpuTicks), 64);
        assert_eq!(m.limits().limit(Resource::Frames), 16);
        assert_eq!(m.limits().limit(Resource::Processes), 1);
        assert_eq!(m.limits().limit(Resource::Threads), 1);
        assert_eq!(
            Budget::new(m.restart_policy()).admit(0),
            Err(RecoveryRequired::BudgetExhausted)
        );
        let mut authority = Authority::new();
        let custody = authority.create_space().unwrap();
        let branches = authority.create_space().unwrap();
        let destination = authority.create_space().unwrap();
        let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
        let roots = [
            authority
                .create_root(custody, Kind::Memory, common | Rights::READ)
                .unwrap(),
            authority
                .create_root(
                    custody,
                    Kind::Endpoint,
                    common | Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
                )
                .unwrap(),
            authority
                .create_root(custody, Kind::Job, common | Rights::READ | Rights::CONTROL)
                .unwrap(),
            authority
                .create_root(custody, Kind::Memory, common | Rights::READ)
                .unwrap(),
            authority
                .create_root(custody, Kind::Memory, common | Rights::READ)
                .unwrap(),
            authority
                .create_root(
                    custody,
                    Kind::Endpoint,
                    common | Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
                )
                .unwrap(),
        ];
        let wrong = [
            CatalogEntry {
                selector: 1,
                root: roots[0],
                kind: Kind::Memory,
            },
            CatalogEntry {
                selector: 2,
                root: roots[1],
                kind: Kind::Endpoint,
            },
        ];
        assert_eq!(
            bootstrap_binding::install_scoped(
                &mut authority,
                custody,
                branches,
                destination,
                &wrong,
                &m
            )
            .err(),
            Some(bootstrap_binding::Error::AuthorityDigest)
        );
        let catalog = [
            CatalogEntry {
                selector: 1,
                root: roots[4],
                kind: Kind::Memory,
            },
            CatalogEntry {
                selector: 2,
                root: roots[5],
                kind: Kind::Endpoint,
            },
        ];
        let installed = bootstrap_binding::install_scoped(
            &mut authority,
            custody,
            branches,
            destination,
            &catalog,
            &m,
        )
        .unwrap();
        let grants = installed.grants.grants.handles();
        assert_eq!(grants.len(), 2);
        assert_eq!(
            authority
                .authorize(destination, grants[0], Kind::Memory, Rights::READ)
                .unwrap()
                .identity(),
            4
        );
        assert_eq!(
            authority
                .authorize(destination, grants[1], Kind::Endpoint, Rights::SEND)
                .unwrap()
                .identity(),
            5
        );
        assert_eq!(
            authority
                .authorize(destination, grants[0], Kind::Memory, Rights::WRITE)
                .err(),
            Some(Error::Denied)
        );
        assert_eq!(
            authority
                .authorize(destination, grants[1], Kind::Endpoint, Rights::CONTROL)
                .err(),
            Some(Error::Denied)
        );
    }
    #[test]
    fn custody_profile_preserves_root_limits_and_bounds_attempts_without_window_refill() {
        use ev_kernel::{
            restart::{Budget, RecoveryRequired},
            scheduler::Resource,
        };
        let image = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let bytes = selected_manifest(image, "custody-graph");
        for name in ["custody-exit", "custody-watchdog"] {
            assert_eq!(selected_manifest(image, name), bytes);
        }
        let m = ev_kernel::bootstrap_manifest::verify(
            &bytes,
            Sha256::digest(&bytes).into(),
            image,
            ev_userspace_contract::ABI,
        )
        .unwrap();
        assert_eq!(m.limits().limit(Resource::CpuTicks), 1000);
        assert_eq!(m.limits().limit(Resource::Frames), 64);
        assert_eq!(m.limits().limit(Resource::Processes), 4);
        assert_eq!(m.limits().limit(Resource::Threads), 8);
        assert_eq!(m.grants().count(), 4);
        assert_eq!(
            u64::from_le_bytes(bytes[120..128].try_into().unwrap()),
            4096
        );
        let mut budget = Budget::new(m.restart_policy());
        for now in [0, 1, 2] {
            assert!(budget.admit(now).is_ok());
        }
        assert_eq!(budget.admit(60), Err(RecoveryRequired::BudgetExhausted));
    }
    #[test]
    fn custody_integrity_cases_keep_good_measurements_and_reject_wrong_authority_before_mint() {
        use ev_kernel::{
            bootstrap_binding::{self, CatalogEntry},
            bootstrap_manifest::{self, Error},
            capability::{Authority, Kind, Rights},
        };
        let image = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let bytes = selected_manifest(image, "custody-graph");
        let measurement = Sha256::digest(&bytes).into();
        let fixtures = custody_integrity_fixtures(image, &bytes);
        assert_eq!(
            bootstrap_manifest::verify(
                &fixtures.corrupt_manifest,
                measurement,
                image,
                ev_userspace_contract::ABI
            )
            .err(),
            Some(Error::ManifestDigest)
        );
        assert_eq!(
            bootstrap_manifest::verify(
                &bytes,
                measurement,
                &fixtures.corrupt_image,
                ev_userspace_contract::ABI
            )
            .err(),
            Some(Error::ImageDigest)
        );
        let wrong = bootstrap_manifest::verify(
            &fixtures.wrong_authority_manifest,
            fixtures.wrong_authority_measurement,
            image,
            ev_userspace_contract::ABI,
        )
        .unwrap();
        let good =
            bootstrap_manifest::verify(&bytes, measurement, image, ev_userspace_contract::ABI)
                .unwrap();
        let mut authority = Authority::new();
        let custody = authority.create_space().unwrap();
        let branches = authority.create_space().unwrap();
        let destination = authority.create_space().unwrap();
        let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
        let kinds = [Kind::Memory, Kind::Endpoint, Kind::Job, Kind::Memory];
        let rights = [
            Rights::READ,
            Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
            Rights::READ | Rights::CONTROL,
            Rights::READ,
        ];
        let catalog: [CatalogEntry; 4] = core::array::from_fn(|i| CatalogEntry {
            selector: i as u64 + 1,
            root: authority
                .create_root(custody, kinds[i], common | rights[i])
                .unwrap(),
            kind: kinds[i],
        });
        assert_eq!(
            bootstrap_binding::install_scoped(
                &mut authority,
                custody,
                branches,
                destination,
                &catalog,
                &wrong
            )
            .err(),
            Some(bootstrap_binding::Error::AuthorityDigest)
        );
        // Installation into the same two empty tables must still succeed: the
        // rejected authority selection cannot leave grants behind in either.
        assert!(
            bootstrap_binding::install_scoped(
                &mut authority,
                custody,
                branches,
                destination,
                &catalog,
                &good
            )
            .is_ok()
        );
    }

    #[test]
    fn discipline_profile_declares_only_role_endpoints_and_optional_mutex() {
        use ev_kernel::capability::{Kind, Rights};
        let depth = discipline_roles(true);
        let chain = discipline_roles(false);
        assert_eq!(depth.len(), 6);
        assert_eq!(chain.len(), 7);
        for (i, role) in depth.iter().enumerate() {
            assert_eq!(role.selector, i as u64 + 1);
            assert_eq!(role.kind, Kind::Endpoint);
            assert_eq!(role.rights.bits(), if i % 2 == 0 { 272 } else { 8 });
            assert_eq!(chain[i], *role);
        }
        assert_eq!(chain[6].selector, 7);
        assert_eq!(chain[6].kind, Kind::Mutex);
        assert_eq!(chain[6].rights, Rights::CONTROL);
    }
    #[test]
    fn block_transport_roles_keep_ports_out_of_the_client() {
        use ev_kernel::capability::Kind;
        let driver = m3_transport_roles(true);
        let client = m3_transport_roles(false);
        assert_eq!(driver.len(), 3);
        assert_eq!(client.len(), 2);
        assert_eq!(
            (driver[0].selector, driver[0].kind, driver[0].rights.bits()),
            (1, Kind::IoPorts, 3)
        );
        assert_eq!(
            (driver[1].selector, driver[1].kind, driver[1].rights.bits()),
            (2, Kind::Memory, 7)
        );
        assert_eq!(
            (driver[2].selector, driver[2].kind, driver[2].rights.bits()),
            (3, Kind::Endpoint, 272)
        );
        assert_eq!(
            (client[0].selector, client[0].kind, client[0].rights.bits()),
            (1, Kind::Memory, 7)
        );
        assert_eq!(
            (client[1].selector, client[1].kind, client[1].rights.bits()),
            (2, Kind::Endpoint, 8)
        );
        assert!(!client.iter().any(|r| r.kind == Kind::IoPorts));
    }
    #[test]
    fn production_profile_selection_preserves_ordinary_and_stress_limits() {
        use ev_kernel::scheduler::Resource;
        let image = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        for name in ["normal", "fault"] {
            assert_eq!(selected_manifest(image, name), manifest(image, false));
        }
        for name in ["graph", "graph-fault", "graph-rpc", "graph-rpc-timeout"] {
            assert_eq!(selected_manifest(image, name), manifest(image, true));
        }
        for name in ["generation-good", "generation-bad", "generation-silent"] {
            let bytes = selected_manifest(image, name);
            let parsed = ev_kernel::bootstrap_manifest::verify(
                &bytes,
                Sha256::digest(&bytes).into(),
                image,
                ev_userspace_contract::ABI,
            )
            .unwrap();
            for (resource, limit) in [
                Resource::CpuTicks,
                Resource::Frames,
                Resource::Processes,
                Resource::Threads,
            ]
            .into_iter()
            .zip(GENERATION_POLICY)
            {
                assert_eq!(parsed.limits().limit(resource), limit);
            }
            assert_eq!(parsed.grants().count(), 2);
        }
        let bytes = selected_manifest(image, "graph-restart");
        let m = ev_kernel::bootstrap_manifest::verify(
            &bytes,
            Sha256::digest(&bytes).into(),
            image,
            ev_userspace_contract::ABI,
        )
        .unwrap();
        assert_eq!(
            m.limits().limit(Resource::CpuTicks),
            ev_kernel::service::RESTART_SERVICE_LIMITS.limit(Resource::CpuTicks)
        );
        assert_eq!(m.limits().limit(Resource::Frames), 64);
        assert_eq!(m.grants().count(), 4);
    }
    #[test]
    fn producer_abi_and_manifest_measure_exact_source_image() {
        assert_eq!(
            Sha256::digest(ev_userspace_contract::ABI_DESCRIPTION).as_slice(),
            ev_userspace_contract::ABI
        );
        let image = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let bytes = manifest(image, false);
        let digest = Sha256::digest(&bytes).into();
        let verified = ev_kernel::bootstrap_manifest::verify(
            &bytes,
            digest,
            image,
            ev_userspace_contract::ABI,
        )
        .unwrap();
        let plan = ev_kernel::executable::Image::from_manifest(&verified).unwrap();
        assert_eq!(plan.required_frames(), 10);
        assert!(plan.bootstrap_page().is_some());
        let mut changed = *image;
        changed[4096] ^= 1;
        assert!(
            ev_kernel::bootstrap_manifest::verify(
                &bytes,
                digest,
                &changed,
                ev_userspace_contract::ABI
            )
            .is_err()
        );
    }
}

mod desktop_graph;
pub(crate) use desktop_graph::extend_desktop_graph;

mod native_graph;
pub(crate) use native_graph::extend_native_graph;

pub(crate) mod provider_graph;
pub(crate) use provider_graph::extend_provider_graph;

pub(crate) mod ipc_bench_graph;
