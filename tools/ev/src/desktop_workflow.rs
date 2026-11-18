//! Full graph development workflow and independent desktop disk observer.
//! Raw snapshots are read only; no formatter, recovery write or user data repair
//! runs on the guest's behalf. Every actual scanout is retained unmodified.
use crate::{build::Result, storage};
use ev_file::{
    Envelope,
    desktop::{Object, SEED_NOTES, SEED_PRIVATE},
};
use ev_store::{
    GenerationId, GenerationManifest, ObjectId, Sector, SectorIo, Store, desktop::Region,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn link(path: &std::path::Path, base: &std::path::Path) -> Result<Value> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err("desktop evidence must be a regular file".into());
    }
    Ok(
        json!({"path":path.strip_prefix(base).map_err(|_|"desktop evidence escaped directory")?,"sha256":crate::build::hash_file(path)?}),
    )
}
fn optional_link(path: &std::path::Path, base: &std::path::Path) -> Result<Option<Value>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => link(path, base).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn build_id(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("desktop build input identity malformed".into());
    }
    let mut out = [0; 32];
    for (i, n) in out.iter_mut().enumerate() {
        *n = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
fn retain_components(
    root: &std::path::Path,
    evidence: &std::path::Path,
    manifest: &crate::build::Manifest,
) -> Result<Value> {
    use ev_kernel::{
        capability::{Kind, Rights},
        executable::LayoutReservation,
        scheduler::Limits,
        service::{Role, ServiceImage},
    };
    use ev_userspace_contract::root_v2::{
        self,
        catalogue::{Catalogue, Provenance},
        graph::{self, CHILDREN},
    };
    let output = root.join("build/m0");
    let directory = evidence.join("components");
    std::fs::create_dir(&directory).map_err(|e| e.to_string())?;
    if manifest.supervisor.len() > 512 {
        return Err("desktop component count exceeds bounded manifest".into());
    }
    let mut components = Vec::new();
    let mut source = Vec::new();
    let mut total = 0usize;
    for (i, a) in manifest.supervisor.iter().enumerate() {
        let path = crate::build::verify_artifact(&output, a)?;
        let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 8 * 1024 * 1024 {
            return Err("desktop source component nonregular/oversized".into());
        }
        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        total = total
            .checked_add(bytes.len())
            .ok_or("desktop retained size overflow")?;
        if total > 256 * 1024 * 1024 {
            return Err("desktop retained components exceed256MiB".into());
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("desktop component basename invalid")?;
        let retained = directory.join(format!("{i:03}-{name}"));
        storage::immutable_new(&retained, &bytes)?;
        components.push(json!({"build_artifact":a,"retained":link(&retained,evidence)?}));
        source.push((a, bytes));
    }
    let mut catalogues = source.iter().filter(|(_, b)| b.starts_with(b"EVGRAPH1"));
    let (catalogue_artifact, catalogue_bytes) = catalogues
        .next()
        .ok_or("actual full desktop catalogue missing")?;
    if catalogues.next().is_some() {
        return Err("ambiguous actual desktop catalogue".into());
    }
    let catalogue =
        Catalogue::decode(catalogue_bytes).map_err(|e| format!("desktop catalogue: {e:?}"))?;
    if ev_root_supervisor::desktop_plan::graph_measurement(&catalogue)
        != catalogue.graph_measurement()
    {
        return Err("desktop catalogue graph description measurement differs".into());
    }
    let identity = build_id(&manifest.build_id)?;
    if catalogue.kernel_input() != identity
        || catalogue.app_id() != crate::native_package::HELLO_APP_ID
        || catalogue.provenance() != Provenance::Zion
        || catalogue.app_build() != identity
    {
        return Err(
            "desktop catalogue kernel/App/package identity differs from retained build".into(),
        );
    }
    let image_for = |hash: [u8; 32]| -> Result<&[u8]> {
        source
            .iter()
            .find(|(_, b)| <[u8; 32]>::from(Sha256::digest(b)) == hash && b.starts_with(b"\x7fELF"))
            .map(|(_, b)| b.as_slice())
            .ok_or("desktop measured image absent from retained artifacts".into())
    };
    let root_image = image_for(catalogue.root_image())?;
    let mut images = Vec::new();
    for (child, image) in CHILDREN.into_iter().zip(catalogue.images()) {
        if ev_root_supervisor::desktop_plan::roles_measurement(child) != image.roles {
            return Err(
                "desktop child role measurement differs from actual source-defined wiring".into(),
            );
        }
        if image.role != child.image() {
            return Err("desktop catalogue child order differs".into());
        }
        let bytes = image_for(image.image)?;
        let roles: Vec<Role> = graph::grants(child)
            .iter()
            .enumerate()
            .map(|(i, g)| {
                Ok(Role {
                    selector: i as u64 + 1,
                    kind: match g.kind {
                        1 => Kind::Memory,
                        2 => Kind::Endpoint,
                        7 => Kind::IoPorts,
                        8 => Kind::Display,
                        _ => return Err("desktop child kind invalid"),
                    },
                    rights: Rights::from_bits(g.rights).ok_or("desktop child rights invalid")?,
                })
            })
            .collect::<core::result::Result<_, &str>>()
            .map_err(str::to_owned)?;
        let layout = if image.display_layout {
            LayoutReservation::DisplayApertureV1
        } else {
            LayoutReservation::Legacy
        };
        let admitted = ServiceImage::verify_layout(
            bytes,
            image.image,
            Limits::new(
                image.limits[0],
                image.limits[1],
                image.limits[2],
                image.limits[3],
            ),
            &roles,
            layout,
        )
        .map_err(|e| format!("desktop retained child descriptor: {e:?}"))?;
        if admitted.digest() != image.descriptor {
            return Err(
                "desktop catalogue descriptor differs from actual image/roles/limits/layout".into(),
            );
        }
        images.push(json!({"role":image.role.selector(),"image_sha256":image.image,"descriptor":image.descriptor,"grants":image.grants,"display_layout":image.display_layout}));
    }
    let app_image = catalogue
        .images()
        .find(|i| i.role == root_v2::Role::AppImage)
        .ok_or("desktop App image missing")?;
    let package = crate::native_package::hello(image_for(app_image.image)?, identity)?;
    if package.package != catalogue.package() || !source.iter().any(|(_, b)| b == &package.bytes) {
        return Err(
            "actual self-contained Hello.zion/package/cohort binding missing or mismatched".into(),
        );
    }
    let catalogue_hash: [u8; 32] = Sha256::digest(catalogue_bytes).into();
    let roots: Vec<_> = source
        .iter()
        .filter(|(_, b)| {
            b.starts_with(b"EVBM0002")
                && b.get(16..48) == Some(catalogue.root_image().as_slice())
                && b.get(176..208) == Some(catalogue_hash.as_slice())
        })
        .collect();
    if roots.len() != 1 {
        return Err("actual Root v2 manifest does not uniquely bind image/catalogue".into());
    }
    let root_manifest = roots[0];
    let root_digest: [u8; 32] = Sha256::digest(&root_manifest.1).into();
    let measured_root =
        ev_kernel::root_manifest_v2::verify(&root_manifest.1, root_digest, root_image)
            .map_err(|e| format!("desktop Root manifest: {e:?}"))?
            .current_profile()
            .map_err(|e| format!("desktop Root18roles: {e:?}"))?;
    let expected_root = root_v2::manifest_profile(root_v2::ManifestInputs {
        root_image: catalogue.root_image(),
        catalogue: catalogue_hash,
        authority: measured_root.manifest().expected_authority_digest(),
        limits: ev_root_supervisor::desktop_plan::ROOT_LIMITS,
        restart_attempts: ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS,
        restart_window: ev_root_supervisor::desktop_plan::RESTART_WINDOW,
    })
    .map_err(|e| format!("desktop canonical Root profile: {e:?}"))?;
    if expected_root != root_manifest.1.as_slice()
        || catalogue.restart_attempts() != ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS
        || catalogue.restart_window() != ev_root_supervisor::desktop_plan::RESTART_WINDOW
    {
        return Err(
            "desktop Root limits/restart policy differ from actual source-defined profile".into(),
        );
    }
    let value = json!({"schema":1,"build_input_id":manifest.build_id,"catalogue":catalogue_artifact,"root_manifest":root_manifest.0,"root_image_sha256":catalogue.root_image(),"app_id":catalogue.app_id(),"package_id":catalogue.package(),"app_build":catalogue.app_build(),"cohort":images,"components":components,"binding":"retained source-built exact cohort, App package and Root measured manifest; integrity/admission checks, no publisher authentication"});
    storage::json_new(&evidence.join("component-binding.json"), &value)?;
    Ok(value)
}

pub fn run() -> Result<()> {
    use crate::{
        boot::{self, DesktopBoot},
        build::{self, Manifest},
        cli::{BootOptions, BuildOptions},
    };
    use std::{fs, path::Path};
    let current = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = crate::doctor::workspace(&current, None)?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let parent = storage::directory_beneath(&root, Path::new("build/m4/evidence"))?;
    let evidence = build::unique_directory(&parent, "desktop-graph")?;
    println!("Evidence: {}", evidence.display());
    let mut stage = "build";
    let mut components = None;
    let mut retained = None;
    let mut disk_before = None;
    let mut disk_after = None;
    let mut validation = None;
    let mut boots = 0;
    let result: Result<()> = (|| {
        build::build(&BuildOptions {
            root: Some(root.clone()),
            fixture: Some("m4-desktop".into()),
            ..BuildOptions::default()
        })?;
        stage = "retain_manifest";
        let bytes = fs::read(root.join("build/m0/manifest.json")).map_err(|e| e.to_string())?;
        let path = evidence.join("manifest.json");
        storage::immutable_new(&path, &bytes)?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        manifest.validate_policy_rows()?;
        if manifest.fixture.as_deref() != Some("m4-desktop") {
            return Err("wrong desktop fixture in retained manifest".into());
        }
        retained = Some(
            json!({"record":link(&path,&evidence)?,"build_id":manifest.build_id,"source_inputs":manifest.source_inputs,"source_sha256":manifest.source_sha256,"kernel":manifest.kernel,"boot_image":manifest.image}),
        );
        stage = "component_binding";
        components = Some(retain_components(&root, &evidence, &manifest)?);
        stage = "fresh_private_disk";
        let disk = storage::Disk::create(&root, &evidence)?;
        let before = disk.bytes()?;
        disk_before = Some(disk.capture(&evidence, "data-before.raw")?);
        stage = "actual_desktop_graph";
        boots += 1;
        let boot = boot::boot_desktop(
            &BootOptions {
                root: Some(root.clone()),
                timeout_seconds: 180,
                ..BootOptions::default()
            },
            DesktopBoot {
                manifest: &path,
                evidence: &evidence,
                disk: &disk,
            },
        );
        disk_after = Some(disk.capture(&evidence, "data-after.raw")?);
        let after = disk.bytes()?;
        disk.seal()?;
        boot?;
        stage = "independent_read_only_cold_disk";
        let serial =
            fs::read(evidence.join("boot/run-001/serial.log")).map_err(|e| e.to_string())?;
        validation = Some(
            json!({"disk":inspect_disk(&before,&after)?,"lifecycle":crate::desktop_protocol::record(&serial,&manifest.build_id)?,"checkpoints":crate::desktop_protocol::steps(&serial,&manifest.build_id)?}),
        );
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
        "boot/run-001/desktop-observer.json",
    ] {
        match optional_link(&evidence.join(name), &evidence) {
            Ok(Some(v)) => artifacts.push(v),
            Ok(None) => {}
            Err(e) => {
                link_error = Some(e);
                break;
            }
        }
    }
    match fs::read_dir(evidence.join("boot/run-001")) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry)
                        if entry
                            .file_name()
                            .to_str()
                            .is_some_and(|n| n.starts_with("screen-") && n.ends_with(".ppm")) =>
                    {
                        match link(&entry.path(), &evidence) {
                            Ok(v) => artifacts.push(v),
                            Err(e) => link_error = Some(e),
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        link_error = Some(e.to_string());
                        break;
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => link_error = Some(e.to_string()),
    }
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"desktop-graph","passed":result.is_ok()&&link_error.is_none(),"last_stage":stage,"error":result.as_ref().err(),"evidence_link_error":link_error,"build":retained,"components":components,"expected_boots":1,"boot_invocations":boots,"disk_before":disk_before,"disk_after":disk_after,"validation":validation,"artifacts":artifacts,"method":"One retained source-built desktop cohort, one fresh VM/private disk and real PS2 make-break/QMP/UART stimulus; actual guest receipts and fault/replacement lifecycle plus independent source pixel/package/disk checks. Bounded development proof, no automatic whole-M4/0.1 acceptance."}),
    )?;
    println!("Evidence: {}", evidence.display());
    result?;
    if let Some(error) = link_error {
        return Err(error);
    }
    println!(
        "PASS desktop-graph: actual native desktop cohort, selected-file grants and contained App/Shell recovery with retained source/package/device evidence."
    );
    Ok(())
}

const SNAPSHOT_DEADLINE: u64 = 1;
#[derive(Debug)]
enum SnapshotError {
    Bounds,
    Deadline,
    ReadOnly,
}
struct RegionSnapshot<'a> {
    bytes: &'a [u8],
    region: Region,
    reads: u64,
    mutations: u64,
}
impl<'a> RegionSnapshot<'a> {
    fn new(bytes: &'a [u8], region: Region) -> Result<Self> {
        if bytes.len() != storage::DISK_BYTES {
            return Err("desktop snapshot must be the exact runner-owned4MiB disk".into());
        }
        Ok(Self {
            bytes,
            region,
            reads: 0,
            mutations: 0,
        })
    }
}
impl SectorIo for RegionSnapshot<'_> {
    type Error = SnapshotError;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(
        &mut self,
        lba: u64,
        out: &mut Sector,
        deadline: u64,
    ) -> core::result::Result<(), Self::Error> {
        if deadline != SNAPSHOT_DEADLINE {
            return Err(SnapshotError::Deadline);
        }
        if lba >= self.sectors() {
            return Err(SnapshotError::Bounds);
        }
        let start =
            (u64::from(self.region.physical_start()) + lba) as usize * storage::SECTOR_BYTES;
        let bytes = self
            .bytes
            .get(start..start + storage::SECTOR_BYTES)
            .ok_or(SnapshotError::Bounds)?;
        out.copy_from_slice(bytes);
        self.reads += 1;
        Ok(())
    }
    fn write(&mut self, _: u64, _: &Sector, _: u64) -> core::result::Result<(), Self::Error> {
        self.mutations += 1;
        Err(SnapshotError::ReadOnly)
    }
    fn flush(&mut self, _: u64) -> core::result::Result<(), Self::Error> {
        self.mutations += 1;
        Err(SnapshotError::ReadOnly)
    }
}
fn pending(object: Object) -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [object.stable_id() as u8; 32],
        supervisor_image: [0x22; 32],
        abi: ev_userspace_contract::ABI,
        health_contract: [0x33; 32],
        health_version: 1,
        required_checks: 3,
    }
}
fn inspect_file(bytes: &[u8], object: Object) -> Result<Value> {
    let (region, payload) = match object {
        Object::Notes => (Region::FileA, SEED_NOTES),
        Object::Private => (Region::FileB, SEED_PRIVATE),
    };
    let mut store =
        Store::open(RegionSnapshot::new(bytes, region)?, SNAPSHOT_DEADLINE).map_err(|e| {
            format!(
                "desktop {object:?} cannot cold-open without repair: {:?}",
                e.error
            )
        })?;
    if store
        .selected_manifest(SNAPSHOT_DEADLINE)
        .map_err(|e| format!("desktop File manifest: {e:?}"))?
        != pending(object)
        || store.known_good().is_some()
        || store
            .committed_boot_serial()
            .map_err(|e| format!("desktop File bootserial: {e:?}"))?
            != 0
        || store
            .highest_generation()
            .map_err(|e| format!("desktop File generation: {e:?}"))?
            != 1
        || store
            .next_operation()
            .map_err(|e| format!("desktop File operation: {e:?}"))?
            .get()
            != 1
        || store
            .last_failure()
            .map_err(|e| format!("desktop File failure: {e:?}"))?
            .is_some()
    {
        return Err("desktop File metadata changed without authorized replace/admission".into());
    }
    let mut body = [0; ev_store::PAYLOAD_BYTES];
    let length = store
        .read_mutable(ObjectId::user_data(), &mut body, SNAPSHOT_DEADLINE)
        .map_err(|e| format!("desktop File payload: {e:?}"))?;
    let envelope =
        Envelope::decode(&body[..length]).map_err(|e| format!("desktop File envelope: {e:?}"))?;
    if envelope.counter() != 0 || envelope.global_operation() != 0 || envelope.payload() != payload
    {
        return Err(format!(
            "desktop {object:?} seed/counter/receipt was overwritten"
        ));
    }
    let payload_sha256 = format!("{:x}", Sha256::digest(envelope.payload()));
    let device = store.into_device();
    if device.mutations != 0 {
        return Err("desktop observer attempted a repair/write/flush".into());
    }
    let start = region.physical_start() as usize * storage::SECTOR_BYTES;
    let end = start + ev_store::REQUIRED_SECTORS as usize * storage::SECTOR_BYTES;
    Ok(
        json!({"object":object.stable_id(),"region_start":region.physical_start(),"sectors":ev_store::REQUIRED_SECTORS,"raw_sha256":format!("{:x}",Sha256::digest(&bytes[start..end])),"payload_sha256":payload_sha256,"client_counter":0,"global_operation":0,"pending_data_container":true,"known_good":null,"reads":device.reads,"mutation_attempts":device.mutations}),
    )
}
fn inspect_disk(before: &[u8], after: &[u8]) -> Result<Value> {
    if before.len() != storage::DISK_BYTES || after.len() != storage::DISK_BYTES {
        return Err("desktop disk size changed".into());
    }
    for (index, (a, b)) in before.iter().zip(after).enumerate() {
        let sector = index / storage::SECTOR_BYTES;
        if !((32..46).contains(&sector) || (48..62).contains(&sector)) && a != b {
            return Err(format!(
                "desktop changed guard/unowned sector{sector} byte{index}"
            ));
        }
    }
    Ok(
        json!({"notes":inspect_file(after,Object::Notes)?,"private":inspect_file(after,Object::Private)?,"guards_unchanged":true,"system_region_unchanged":true,"system_health":"unused/unproven in this M4 fixture; no KnownGood inference from GUI","observer":"read-only cold raw Store-v2; no repair; counters/receipt and exact source-defined seeds"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_store::BootPolicy;
    struct Writable {
        bytes: Vec<u8>,
        region: Region,
    }
    impl SectorIo for Writable {
        type Error = ();
        fn sectors(&self) -> u64 {
            ev_store::REQUIRED_SECTORS
        }
        fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> core::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            let start = (u64::from(self.region.physical_start()) + lba) as usize * 512;
            out.copy_from_slice(&self.bytes[start..start + 512]);
            Ok(())
        }
        fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> core::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            let start = (u64::from(self.region.physical_start()) + lba) as usize * 512;
            self.bytes[start..start + 512].copy_from_slice(bytes);
            Ok(())
        }
        fn flush(&mut self, _: u64) -> core::result::Result<(), ()> {
            Ok(())
        }
    }
    fn formatted() -> (Vec<u8>, Vec<u8>) {
        let before = vec![0; storage::DISK_BYTES];
        let mut bytes = before.clone();
        for (object, region, payload) in [
            (Object::Notes, Region::FileA, SEED_NOTES),
            (Object::Private, Region::FileB, SEED_PRIVATE),
        ] {
            let mut envelope = [0; 256];
            let n = Envelope::initial(payload).unwrap().encode(&mut envelope);
            bytes = Store::format_new(
                Writable { bytes, region },
                pending(object),
                &envelope[..n],
                BootPolicy::new(3).unwrap(),
                1,
            )
            .map_err(|e| e.error)
            .unwrap()
            .into_device()
            .bytes;
        }
        (before, bytes)
    }
    #[test]
    fn cold_files_are_independently_opened_without_backend_mutation() {
        let (before, after) = formatted();
        let actual = inspect_disk(&before, &after).unwrap();
        assert_eq!(actual["notes"]["region_start"], 32);
        assert_eq!(actual["private"]["region_start"], 48);
        assert_eq!(actual["notes"]["mutation_attempts"], 0);
        assert_eq!(actual["private"]["mutation_attempts"], 0);
        assert_ne!(
            actual["notes"]["payload_sha256"],
            actual["private"]["payload_sha256"]
        );
    }
    #[test]
    fn only_two_file_regions_may_change_and_system_health_is_not_fabricated() {
        let (before, after) = formatted();
        assert!(inspect_disk(&before, &after).is_ok());
        for sector in [0, 1, 2, 15, 16, 29, 30, 31, 46, 47, 62, 8191] {
            let mut bad = after.clone();
            bad[sector * 512] ^= 1;
            assert!(inspect_disk(&before, &bad).is_err());
        }
        let mut wrong = after.clone();
        let notes = wrong[32 * 512..46 * 512].to_vec();
        wrong[48 * 512..62 * 512].copy_from_slice(&notes);
        assert!(inspect_disk(&before, &wrong).is_err());
        assert!(inspect_disk(&before, &after[..after.len() - 1]).is_err());
    }
    #[test]
    fn malformed_or_uncommitted_file_requires_refusal_instead_of_host_repair() {
        let (before, after) = formatted();
        // Only the committed root and its referenced immutable/data records are
        // required here. The unused alternate root is not fabricated evidence.
        for sector in [33, 42, 44, 49, 58, 60] {
            let mut bad = after.clone();
            bad[sector * 512] ^= 0xff;
            assert!(inspect_disk(&before, &bad).is_err());
        }
        let mut region = RegionSnapshot::new(&after, Region::FileA).unwrap();
        let mut b = [0; 512];
        assert!(region.read(14, &mut b, 1).is_err());
        assert!(region.read(0, &mut b, 2).is_err());
        assert!(region.write(0, &b, 1).is_err());
        assert!(region.flush(1).is_err());
        assert_eq!(region.mutations, 2);
    }
}
