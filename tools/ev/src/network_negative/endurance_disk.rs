//! Read-only Endurance Store checks. No formatter, write, flush, repair or
//! recovery fallback is available through the captured byte adapter.
use super::note;
use crate::{build::Result, storage};
use ev_app_registry::{Policy, Registry, app_data::AppDataEnvelope, note_data::NoteDataEnvelope};
use ev_root_supervisor::native_plan::{Contracts, Packages, Slot};
use ev_store::{ObjectId, Sector, SectorIo, Store, native::Region};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
const CUT: u64 = 1 << 20;
struct Media<'a> {
    bytes: &'a [u8],
    first: usize,
    reads: u64,
}
impl SectorIo for Media<'_> {
    type Error = &'static str;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(
        &mut self,
        lba: u64,
        out: &mut Sector,
        cut: u64,
    ) -> core::result::Result<(), Self::Error> {
        if lba >= self.sectors() || cut != CUT {
            return Err("readonly endurance sector/cut");
        }
        let start = self
            .first
            .checked_add(usize::try_from(lba).map_err(|_| "readonly offset")?)
            .and_then(|v| v.checked_mul(512))
            .ok_or("readonly offset")?;
        out.copy_from_slice(
            self.bytes
                .get(start..start + 512)
                .ok_or("readonly extent")?,
        );
        self.reads += 1;
        Ok(())
    }
    fn write(&mut self, _: u64, _: &Sector, _: u64) -> core::result::Result<(), Self::Error> {
        Err("readonly endurance rejects write/repair")
    }
    fn flush(&mut self, _: u64) -> core::result::Result<(), Self::Error> {
        Err("readonly endurance rejects flush/repair")
    }
}
fn open<'a>(bytes: &'a [u8], banks: &Packages<'_>, region: Region) -> Result<Store<Media<'a>>> {
    let creation = if region == Region::SessionNote {
        banks.note_format_manifest()
    } else {
        banks.format_manifest(region)
    };
    Store::open_mutable_namespace(
        Media {
            bytes,
            first: region.physical_start() as usize,
            reads: 0,
        },
        &creation,
        CUT,
    )
    .map_err(|r| format!("endurance original {region:?} creation/open: {:?}", r.error))
}
fn body(store: &mut Store<Media<'_>>) -> Result<[u8; 256]> {
    let mut out = [0; 256];
    if store
        .read_mutable(ObjectId::user_data(), &mut out, CUT)
        .map_err(|e| format!("endurance readonly body: {e:?}"))?
        != 256
    {
        return Err("endurance mutable payload extent".into());
    }
    Ok(out)
}
fn shape(bytes: &[u8]) -> Result<()> {
    if bytes.len() != storage::DISK_BYTES {
        return Err("endurance requires exact captured4MiB disk".into());
    }
    Ok(())
}
fn in_region(sector: usize, region: Region) -> bool {
    let first = region.physical_start() as usize;
    (first..first + ev_store::REQUIRED_SECTORS as usize).contains(&sector)
}
fn changes(before: &[u8], after: &[u8], allowed: impl Fn(usize) -> bool) -> Result<Vec<usize>> {
    shape(before)?;
    shape(after)?;
    let mut changed = Vec::new();
    for (i, (a, b)) in before
        .as_chunks::<512>()
        .0
        .iter()
        .zip(after.as_chunks::<512>().0)
        .enumerate()
    {
        if a != b {
            if !allowed(i) {
                return Err(format!("endurance changed unrelated/preserved sector{i}"));
            }
            changed.push(i);
        }
    }
    Ok(changed)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
/// Exact selected A, original schema epoch and saved Note operation. All stores
/// are opened against the immutable source-built package creation manifests.
pub(super) fn saved(bytes: &[u8], banks: &Packages<'_>, revision: u64) -> Result<Value> {
    shape(bytes)?;
    if !banks.is_network() || !matches!(revision, 2 | 5) {
        return Err("endurance selected package/revision".into());
    }
    let mut store = open(bytes, banks, Region::AppRegistry)?;
    let raw = body(&mut store)?;
    let record = ev_zion::lifecycle::Record::decode(&raw)
        .map_err(|e| format!("endurance Registry: {e:?}"))?;
    if !record.installed()
        || record.app() != banks.app()
        || record.revision() != revision
        || record.data_epoch() != 1
        || record.active().map(|p| p.digest()) != Some(banks.digest(Slot::A))
        || record.staged().is_some()
        || record.previous().map(|p| p.digest())
            != if revision == 2 {
                None
            } else {
                Some(banks.digest(Slot::A))
            }
        || store
            .next_operation()
            .map_err(|e| format!("endurance Registry counter: {e:?}"))?
            .get()
            != revision + 1
    {
        return Err("endurance Registry differs from exact initial/reinstalled A selection".into());
    }
    let device = store.into_device();
    let registry = Registry::open(
        device,
        Policy {
            app: banks.app(),
            abi: ev_userspace_contract::ABI,
            platform: 1,
        },
        banks,
        &Contracts,
        CUT,
    )
    .map_err(|r| {
        format!(
            "endurance readonly Registry package resolution: {:?}",
            r.error
        )
    })?;
    let (device, _, pending) = registry.into_parts();
    if pending.is_some() {
        return Err("endurance retained unresolved Registry publication".into());
    }
    let mut reads = device.reads;
    let mut store = open(bytes, banks, Region::AppData)?;
    let raw = body(&mut store)?;
    let data = AppDataEnvelope::decode(&raw).map_err(|e| format!("endurance scalar: {e:?}"))?;
    if data.app() != banks.app()
        || data.schema_epoch() != 1
        || data.counter() != 0
        || data.value() != 1001
        || store
            .next_operation()
            .map_err(|e| format!("endurance scalar operation: {e:?}"))?
            .get()
            != 1
    {
        return Err("endurance changed scalar1001/counter0/schema/app".into());
    }
    reads += store.into_device().reads;
    let mut store = open(bytes, banks, Region::SessionNote)?;
    let raw = body(&mut store)?;
    let note = NoteDataEnvelope::decode(&raw).map_err(|e| format!("endurance Note: {e:?}"))?;
    if note.app() != banks.app()
        || note.counter() != 1
        || note.note() != note::FIRST
        || store
            .next_operation()
            .map_err(|e| format!("endurance Note operation: {e:?}"))?
            .get()
            != 2
    {
        return Err("endurance changed saved Note text/counter/app".into());
    }
    reads += store.into_device().reads;
    Ok(
        json!({"registry_revision":revision,"active":hex(&banks.digest(Slot::A)),"previous":if revision==5 {Some(hex(&banks.digest(Slot::A)))} else {None},"data_epoch":1,"scalar_value":1001,"scalar_counter":0,"note":note::FIRST,"note_counter":1,"reads":reads,"observer_mutations":0}),
    )
}
/// The entire saved media is preserved through hostile work and replacement,
/// except the exact authenticated Remove/Reinstall/Activate Registry history.
pub(super) fn replacement(before: &[u8], after: &[u8], banks: &Packages<'_>) -> Result<Value> {
    let first = saved(before, banks, 2)?;
    let last = saved(after, banks, 5)?;
    let changed = changes(before, after, |s| in_region(s, Region::AppRegistry))?;
    if changed.is_empty() {
        return Err("endurance Registry replacement history absent".into());
    }
    Ok(
        json!({"schema":1,"kind":"readonly-endurance-replacement","before":first,"after":last,"changed_registry_sectors":changed,"all_other_bytes_unchanged":true,"before_sha256":hex(&Sha256::digest(before)),"after_sha256":hex(&Sha256::digest(after))}),
    )
}
pub(super) fn from_seed(seed: &[u8], after: &[u8], banks: &Packages<'_>) -> Result<Value> {
    shape(seed)?;
    for region in [Region::AppRegistry, Region::AppData, Region::SessionNote] {
        let first = region.physical_start() as usize * 512;
        if seed[first..first + ev_store::REQUIRED_SECTORS as usize * 512]
            .iter()
            .any(|b| *b != 0)
        {
            return Err("endurance actual seed namespace was not exactly blank".into());
        }
    }
    let changed = changes(seed, after, |s| {
        [Region::AppRegistry, Region::AppData, Region::SessionNote]
            .into_iter()
            .any(|r| in_region(s, r))
    })?;
    let state = saved(after, banks, 5)?;
    Ok(
        json!({"schema":1,"kind":"readonly-endurance-final-seed","state":state,"changed_sectors":changed,"all_other_bytes_unchanged":true,"seed_sha256":hex(&Sha256::digest(seed)),"after_sha256":hex(&Sha256::digest(after))}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_root_supervisor::native_plan::{
        network_base_graph_measurement, network_layout_measurement, network_roles_measurement,
    };
    use ev_store::{BootPolicy, OperationId, Request};
    use ev_userspace_contract::{Context, root_v2, root_v4};
    use root_v2::catalogue as base;
    use root_v4::{
        catalogue as nc,
        graph::{self, Child},
    };
    fn fixture() -> ([u8; nc::SIZE], Context, Vec<u8>, Vec<u8>) {
        use ev_zion::{
            AppId, Capability, CapabilityRequest, Contract, DataSchema, Platform, Version,
            producer::{Resource, Spec},
        };
        let elf = include_bytes!("../../../../kernel/fixtures/bootstrap-static-v1.elf");
        let app = AppId::new([4; 16]).unwrap();
        let package = |label| {
            ev_zion::producer::build(
                &Spec {
                    app,
                    name: "V4 borrowed metadata model",
                    source: "Repository model only",
                    publisher: None,
                    version: Version {
                        major: 0,
                        minor: 2,
                        patch: label as u32,
                    },
                    build_id: [label; 32],
                    platform: Platform {
                        minimum: 1,
                        target: 1,
                    },
                    abi: ev_userspace_contract::ABI,
                    data_schema: DataSchema {
                        current: 1,
                        oldest_readable: 1,
                    },
                    entrypoint: "bin/main.elf",
                    contracts: &[
                        Contract {
                            name: "ev.app.private-data",
                            major: 1,
                            minimum_minor: 0,
                            features: 0,
                        },
                        Contract {
                            name: "ev.app.session-note",
                            major: 1,
                            minimum_minor: 0,
                            features: 0,
                        },
                    ],
                    capabilities: &[CapabilityRequest {
                        capability: Capability::AppPrivateData,
                        required: true,
                    }],
                },
                elf,
                &[Resource {
                    path: "res/model.txt",
                    bytes: b"V4 actual serialized package model",
                }],
            )
            .unwrap()
        };
        let (a, b) = (package(5), package(6));
        let image: [u8; 32] = Sha256::digest(elf).into();
        let im = |child: Child, tag: u8| nc::Image {
            image: [tag; 32],
            descriptor: [tag + 1; 32],
            abi: ev_userspace_contract::ABI,
            limits: child.limits(),
            roles: network_roles_measurement(child),
        };
        let base_description = base::Description {
            root_image: [1; 32],
            kernel_input: [2; 32],
            graph: [3; 32],
            app_id: app.bytes(),
            package: Sha256::digest(&a).into(),
            app_build: [5; 32],
            provenance: base::Provenance::Zion,
            restart_attempts: 3,
            restart_window: 60000,
            images: core::array::from_fn(|i| {
                let child = graph::CHILDREN[i];
                base::Image {
                    role: root_v2::graph::CHILDREN[i].image(),
                    image: if i == 4 { image } else { [i as u8 + 10; 32] },
                    descriptor: [i as u8 + 20; 32],
                    abi: ev_userspace_contract::ABI,
                    limits: child.limits(),
                    display_layout: i == 5,
                    grants: graph::GRANT_COUNTS[i] as u8,
                    roles: network_roles_measurement(child),
                }
            }),
        };
        let mut base = nc::encode_base(base_description).unwrap();
        let encode = |base: &[u8], layout| {
            nc::encode(nc::Description {
                base,
                app_b: nc::Image {
                    image,
                    ..im(Child::App, 40)
                },
                bad_shell: im(Child::Shell, 50),
                net_driver: im(Child::NetDriver, 60),
                net_service: im(Child::NetService, 70),
                package_b: Sha256::digest(&b).into(),
                package_b_build: [6; 32],
                package_a_bytes: a.len() as u64,
                package_b_bytes: b.len() as u64,
                boot_mode: nc::BootMode::Standalone,
                layout_measurement: layout,
                device: nc::DeviceWitness {
                    mac: nc::REFERENCE_MAC,
                    model_source_sha256: [80; 32],
                    emulator_binary_sha256: [81; 32],
                },
                network_policy: nc::NetworkPolicy {
                    allowed_ipv4: [10, 0, 2, 2],
                    remote_port: 8080,
                    local_port: 49152,
                    dns_name: "example.org",
                },
            })
            .unwrap()
        };
        let draft = encode(&base, [1; 32]);
        let base_hash =
            network_base_graph_measurement(nc::Catalogue::decode(&draft).unwrap().base());
        base[base::MEASUREMENT_OFFSET..base::MEASUREMENT_OFFSET + 32].copy_from_slice(&base_hash);
        let draft = encode(&base, [1; 32]);
        let bytes = encode(
            &base,
            network_layout_measurement(&nc::Catalogue::decode(&draft).unwrap()),
        );
        let mut context = Context {
            epoch: 1,
            incarnation: 2,
            process: 3,
            limits: root_v4::ROOT_LIMITS,
            authority: [4; 32],
            manifest: [0; 32],
        };
        bind(&bytes, &mut context);
        (bytes, context, a, b)
    }
    fn bind(bytes: &[u8], context: &mut Context) {
        let c = nc::Catalogue::decode(bytes).unwrap();
        context.manifest = Sha256::digest(
            root_v4::manifest_profile(root_v2::ManifestInputs {
                root_image: c.base().root_image(),
                catalogue: Sha256::digest(bytes).into(),
                authority: context.authority,
                limits: context.limits,
                restart_attempts: 3,
                restart_window: 60000,
            })
            .unwrap(),
        )
        .into();
    }

    #[derive(Clone)]
    struct Writable {
        bytes: Vec<u8>,
        first: usize,
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
            let start = (self.first + lba as usize) * 512;
            out.copy_from_slice(&self.bytes[start..start + 512]);
            Ok(())
        }
        fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> core::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            let start = (self.first + lba as usize) * 512;
            self.bytes[start..start + 512].copy_from_slice(bytes);
            Ok(())
        }
        fn flush(&mut self, _: u64) -> core::result::Result<(), ()> {
            Ok(())
        }
    }
    fn publish(
        registry: &mut Registry<Writable>,
        banks: &Packages<'_>,
        change: ev_app_registry::Change,
    ) {
        let intent = registry
            .prepare(registry.expected().unwrap(), change, banks, &Contracts)
            .unwrap();
        registry.publish(intent, banks, &Contracts, CUT).unwrap();
    }
    fn saved_media(banks: &Packages<'_>) -> (Vec<u8>, Vec<u8>) {
        let mut seed = vec![0x9b; storage::DISK_BYTES];
        for region in [Region::AppRegistry, Region::AppData, Region::SessionNote] {
            let start = region.physical_start() as usize * 512;
            seed[start..start + ev_store::REQUIRED_SECTORS as usize * 512].fill(0);
        }
        let mut registry = Registry::format_new(
            Writable {
                bytes: seed.clone(),
                first: 64,
            },
            Policy {
                app: banks.app(),
                abi: ev_userspace_contract::ABI,
                platform: 1,
            },
            banks.format_manifest(Region::AppRegistry),
            CUT,
        )
        .map_err(|_| ())
        .unwrap();
        publish(
            &mut registry,
            banks,
            ev_app_registry::Change::Install {
                package: banks.digest(Slot::A),
                data_epoch: 1,
            },
        );
        publish(&mut registry, banks, ev_app_registry::Change::Activate);
        let (mut device, _, pending) = registry.into_parts();
        assert!(pending.is_none());
        device.first = 80;
        let mut device = Store::format_new(
            device,
            banks.format_manifest(Region::AppData),
            &AppDataEnvelope::initial(banks.app(), 1, 1001)
                .unwrap()
                .encode(),
            BootPolicy::new(1).unwrap(),
            CUT,
        )
        .map_err(|_| ())
        .unwrap()
        .into_device();
        device.first = 112;
        let note = NoteDataEnvelope::initial(banks.app(), "").unwrap();
        let mut store = Store::format_new(
            device,
            banks.note_format_manifest(),
            &note.encode(),
            BootPolicy::new(1).unwrap(),
            CUT,
        )
        .map_err(|_| ())
        .unwrap();
        let saved = note.checked_replace(banks.app(), 0, note::FIRST).unwrap();
        store
            .execute(
                OperationId::new(1).unwrap(),
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &saved.encode(),
                },
                CUT,
            )
            .unwrap();
        (seed, store.into_device().bytes)
    }
    fn replaced(before: Vec<u8>, banks: &Packages<'_>) -> Vec<u8> {
        let mut registry = Registry::open(
            Writable {
                bytes: before,
                first: 64,
            },
            Policy {
                app: banks.app(),
                abi: ev_userspace_contract::ABI,
                platform: 1,
            },
            banks,
            &Contracts,
            CUT,
        )
        .map_err(|_| ())
        .unwrap();
        for change in [
            ev_app_registry::Change::Remove,
            ev_app_registry::Change::Reinstall {
                package: banks.digest(Slot::A),
            },
            ev_app_registry::Change::Activate,
        ] {
            publish(&mut registry, banks, change);
        }
        registry.into_parts().0.bytes
    }
    #[test]
    fn actual_store_remove_reinstall_activate_preserves_saved_note_and_scalar_without_writes() {
        let (cat, context, a, b) = fixture();
        let banks = Packages::verify_network(&cat, context, &a, &b).unwrap();
        let (seed, before) = saved_media(&banks);
        let after = replaced(before.clone(), &banks);
        let initial = saved(&before, &banks, 2).unwrap();
        assert_eq!(initial["note_counter"], 1);
        let result = replacement(&before, &after, &banks).unwrap();
        assert_eq!(result["after"]["registry_revision"], 5);
        assert_eq!(result["after"]["observer_mutations"], 0);
        assert!(from_seed(&seed, &after, &banks).is_ok());
        for sector in [
            0, 16, 32, 48, 63, 78, 79, 80, 93, 94, 95, 96, 110, 111, 112, 125, 126, 8191,
        ] {
            let mut bad = after.clone();
            bad[sector * 512 + 7] ^= 1;
            assert!(
                replacement(&before, &bad, &banks).is_err(),
                "sector{sector}"
            );
        }
        assert!(replacement(&after, &after, &banks).is_err());
        assert!(saved(&before, &banks, 5).is_err());
        assert!(saved(&after, &banks, 2).is_err());
        let mut bad_seed = seed.clone();
        bad_seed[80 * 512] = 1;
        assert!(from_seed(&bad_seed, &after, &banks).is_err());
        let mut bad = after.clone();
        bad[16 * 512] ^= 1;
        assert!(from_seed(&seed, &bad, &banks).is_err());
        assert!(from_seed(&seed[..seed.len() - 1], &after, &banks).is_err());
        let mut readonly = Media {
            bytes: &after,
            first: 112,
            reads: 0,
        };
        assert!(readonly.write(0, &[0; 512], CUT).is_err());
        assert!(readonly.flush(CUT).is_err());
        let mut sector = [0; 512];
        assert!(
            readonly
                .read(ev_store::REQUIRED_SECTORS, &mut sector, CUT)
                .is_err()
        );
        assert!(readonly.read(0, &mut sector, 0).is_err());
    }
    #[test]
    fn authenticated_extra_note_operation_and_foreign_creation_refuse_without_repair() {
        let (cat, context, a, b) = fixture();
        let banks = Packages::verify_network(&cat, context, &a, &b).unwrap();
        let (_, before) = saved_media(&banks);
        let after = replaced(before.clone(), &banks);
        let mut store = Store::open_mutable_namespace(
            Writable {
                bytes: after.clone(),
                first: 112,
            },
            &banks.note_format_manifest(),
            CUT,
        )
        .map_err(|_| ())
        .unwrap();
        let mut raw = [0; 256];
        assert_eq!(
            store
                .read_mutable(ObjectId::user_data(), &mut raw, CUT)
                .unwrap(),
            256
        );
        store
            .execute(
                OperationId::new(2).unwrap(),
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &raw,
                },
                CUT,
            )
            .unwrap();
        let duplicate = store.into_device().bytes;
        assert!(saved(&duplicate, &banks, 5).is_err());
        assert!(replacement(&before, &duplicate, &banks).is_err());
        let mut foreign = banks.note_format_manifest();
        foreign.abi[0] ^= 1;
        let mut bytes = after;
        bytes[112 * 512..126 * 512].fill(0);
        let note = NoteDataEnvelope::initial(banks.app(), "").unwrap();
        let mut store = Store::format_new(
            Writable { bytes, first: 112 },
            foreign,
            &note.encode(),
            BootPolicy::new(1).unwrap(),
            CUT,
        )
        .map_err(|_| ())
        .unwrap();
        let note = note.checked_replace(banks.app(), 0, note::FIRST).unwrap();
        store
            .execute(
                OperationId::new(1).unwrap(),
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &note.encode(),
                },
                CUT,
            )
            .unwrap();
        let foreign = store.into_device().bytes;
        let retained = foreign.clone();
        assert!(saved(&foreign, &banks, 5).is_err());
        assert_eq!(foreign, retained);
    }
}
