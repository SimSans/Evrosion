//! Extra readonly gates for the distinct no-App first-use experiment. Existing
//! acquisition and System proof predicates remain unchanged.
use super::*;

fn blank(bytes: &[u8], region: Region) -> Result<()> {
    shape(bytes)?;
    let first = region.physical_start() as usize * 512;
    let end = first + ev_store::REQUIRED_SECTORS as usize * 512;
    if bytes[first..end].iter().any(|b| *b != 0) {
        return Err(format!("first-use {region:?} is not wholly blank"));
    }
    Ok(())
}
fn candidate(
    bytes: &[u8],
    banks: &Packages<'_>,
    expected: [u8; 32],
) -> Result<(acq::Content, Vec<u8>, GenerationManifest)> {
    let store = cold(bytes)?;
    let snapshot = store.snapshot().ok_or("first-use signed snapshot absent")?;
    let content = snapshot.candidate().ok_or("first-use candidate absent")?;
    if content.version != 2
        || content.package != expected
        || snapshot.active().is_some()
        || snapshot.known_good().is_some()
        || snapshot.replay().utc_floor() == 0
        || snapshot.replay().root().version != 1
        || snapshot
            .replay()
            .roles()
            .iter()
            .any(|r| r.is_none_or(|r| r.version != 1))
        || snapshot
            .replay()
            .targets()
            .iter()
            .flatten()
            .map(|t| t.version)
            .collect::<Vec<_>>()
            != [2]
    {
        return Err(
            "first-use candidate, exact retained bundle or fresh replay floors differ".into(),
        );
    }
    let (store, artifact) = selector::stored_package(store, content)?;
    let manifest = manifest(banks, content, &artifact)?;
    if store.into_arena().into_backend().writes != 0 {
        return Err("first-use candidate observer attempted mutation".into());
    }
    Ok((content, artifact, manifest))
}
fn namespace(
    bytes: &[u8],
    banks: &Packages<'_>,
    content: acq::Content,
    artifact: &[u8],
) -> Result<Value> {
    let mut media = Media {
        bytes,
        reads: 0,
        writes: 0,
    };
    let mut registry_store = open_region(&mut media, banks, Region::AppRegistry)?;
    let record = ev_zion::lifecycle::Record::decode(&body(&mut registry_store)?)
        .map_err(|_| "first-use Registry decode")?;
    if !record.installed()
        || record.app() != banks.app()
        || record.revision() != 2
        || record.data_epoch() != 1
        || record.active().is_some()
        || record.staged().map(|v| v.digest()) != Some(content.package)
        || record.previous().is_some()
        || registry_store
            .next_operation()
            .map_err(|_| "first-use Registry operation")?
            .get()
            != 3
    {
        return Err(
            "first-use must stage B over protected installation without any App activation".into(),
        );
    }
    let device = registry_store.into_device();
    let lookup = Lookup {
        banks,
        artifact: Some(artifact),
    };
    let registry = Registry::open(
        device,
        Policy {
            app: banks.app(),
            abi: ev_userspace_contract::ABI,
            platform: 1,
        },
        &lookup,
        &Contracts,
        CUT,
    )
    .map_err(|r| format!("first-use Registry exact package checks: {:?}", r.error))?;
    let (_, _, pending) = registry.into_parts();
    if pending.is_some() {
        return Err("first-use Registry pending publication".into());
    }
    let mut scalar = open_region(&mut media, banks, Region::AppData)?;
    let data =
        AppDataEnvelope::decode(&body(&mut scalar)?).map_err(|_| "first-use scalar decode")?;
    if data.app() != banks.app()
        || data.schema_epoch() != 1
        || data.value() != 1001
        || data.counter() != 0
        || scalar
            .next_operation()
            .map_err(|_| "first-use scalar operation")?
            .get()
            != 1
    {
        return Err("first-use scalar differs from unchanged protected initial envelope".into());
    }
    let _ = scalar;
    if media.writes != 0 {
        return Err("first-use namespace observer attempted mutation".into());
    }
    Ok(
        json!({"registry_revision":2,"active":null,"staged":hex(&content.package),"previous":null,"value":1001,"data_counter":0,"observer_mutations":0}),
    )
}
pub(crate) fn fetched(
    seed: &[u8],
    bytes: &[u8],
    banks: &Packages<'_>,
    package: [u8; 32],
) -> Result<Value> {
    shape(seed)?;
    for region in [
        Region::AppRegistry,
        Region::AppData,
        Region::SessionNote,
        Region::System,
    ] {
        blank(seed, region)?;
    }
    if seed
        .as_chunks::<512>()
        .0
        .iter()
        .enumerate()
        .filter(|(s, _)| content_sector(*s))
        .any(|(_, b)| b.iter().any(|v| *v != 0))
    {
        return Err("first-use seed content was not genuinely blank".into());
    }
    let changed = changes(seed, bytes, |s| {
        content_sector(s)
            || region_sector(s, Region::AppRegistry)
            || region_sector(s, Region::AppData)
    })?;
    blank(bytes, Region::SessionNote)?;
    blank(bytes, Region::System)?;
    let (content, artifact, _) = candidate(bytes, banks, package)?;
    let state = namespace(bytes, banks, content, &artifact)?;
    Ok(
        json!({"kind":"readonly-first-use-fetched-before-Note-or-App","state":state,"seed_sha256":hex(&hash(seed)),"after_sha256":hex(&hash(bytes)),"note_whole_blank":true,"system_whole_blank":true,"candidate_version":2,"candidate_package":hex(&package),"changed_sectors":changed,"all_unrelated_bytes_unchanged":true,"observer_mutations":0}),
    )
}
pub(crate) fn selected(
    before: &[u8],
    after: &[u8],
    banks: &Packages<'_>,
    package: [u8; 32],
) -> Result<Value> {
    blank(before, Region::SessionNote)?;
    blank(before, Region::System)?;
    let changed = changes(before, after, |s| {
        region_sector(s, Region::SessionNote) || region_sector(s, Region::System)
    })?;
    let (content, artifact, manifest) = candidate(after, banks, package)?;
    let state = namespace(after, banks, content, &artifact)?;
    if selector::observe(after, banks)?
        != (selector::Selection::Committed {
            selected: manifest,
            known_good: None,
        })
    {
        return Err(
            "first-use actual System selection differs from exact retained B cohort".into(),
        );
    }
    let saved = super::super::saved_state(
        after,
        banks,
        Saved {
            note: "",
            note_counter: 0,
            value: 1001,
            data_counter: 0,
        },
    )?;
    Ok(
        json!({"kind":"readonly-first-use-selected-after-protected-blank-Note-preparation","state":state,"saved":saved,"generation":2,"known_good":null,"manifest":ev_root_supervisor::native_plan::system::manifest_digest(&manifest),"before_sha256":hex(&hash(before)),"after_sha256":hex(&hash(after)),"changed_sectors":changed,"all_unrelated_bytes_unchanged":true,"observer_mutations":0,"App_Read_or_health_claim":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_io::acquisition_disk::tests::{first_use_created, first_use_fixture};
    fn banks(f: &([u8; 4096], ev_userspace_contract::Context, Vec<u8>, Vec<u8>)) -> Packages<'_> {
        Packages::verify_network(&f.0, f.1, &f.2, &f.3).unwrap()
    }
    #[test]
    fn actual_signed_first_use_separates_fetch_from_note_and_selection_without_repair() {
        let (f, seed, bytes) = first_use_fixture();
        let p = banks(&f);
        let actual = cold(&bytes)
            .unwrap()
            .snapshot()
            .unwrap()
            .candidate()
            .unwrap()
            .package;
        let untouched = bytes.clone();
        let proof = fetched(&seed, &bytes, &p, actual).unwrap();
        assert_eq!(proof["note_whole_blank"], true);
        assert_eq!(proof["state"]["active"], Value::Null);
        let (_, _, manifest) = candidate(&bytes, &p, actual).unwrap();
        let after = first_use_created(&bytes, &p, manifest);
        let proof = selected(&bytes, &after, &p, actual).unwrap();
        assert_eq!(proof["saved"]["note"], "");
        assert_eq!(proof["saved"]["note_counter"], 0);
        assert_eq!(proof["known_good"], Value::Null);
        assert_eq!(bytes, untouched);
        assert!(fetched(&seed, &bytes, &p, [99; 32]).is_err());
        assert!(fetched(&seed, &after, &p, actual).is_err());
        let foreign = crate::network_io::acquisition_disk::tests::fixture::alternate();
        assert!(fetched(&seed, &bytes, &banks(&foreign), actual).is_err());
    }
    #[test]
    fn first_use_refuses_dirty_tail_unrelated_mutation_or_selection_without_actual_note() {
        let (f, seed, bytes) = first_use_fixture();
        let p = banks(&f);
        let actual = cold(&bytes)
            .unwrap()
            .snapshot()
            .unwrap()
            .candidate()
            .unwrap()
            .package;
        assert!(selected(&bytes, &bytes, &p, actual).is_err());
        for sector in [125, 29, 200] {
            let mut changed = bytes.clone();
            changed[sector * 512 + 511] = 1;
            assert!(fetched(&seed, &changed, &p, actual).is_err());
            assert_eq!(changed[sector * 512 + 511], 1);
        }
        let (_, _, manifest) = candidate(&bytes, &p, actual).unwrap();
        let after = first_use_created(&bytes, &p, manifest);
        for sector in [0, 93, 77] {
            let mut changed = after.clone();
            changed[sector * 512 + 511] ^= 1;
            assert!(
                selected(&bytes, &changed, &p, actual).is_err(),
                "sector {sector}"
            );
        }
        // A single redundant header copy or unreferenced padding is not an
        // invalid Store. Destroy the actual entire Note region to test a
        // genuinely unreadable namespace, while retaining every byte as-is.
        let mut corrupt = after.clone();
        corrupt[112 * 512..126 * 512].fill(0x5a);
        let unchanged = corrupt.clone();
        assert!(selected(&bytes, &corrupt, &p, actual).is_err());
        assert_eq!(corrupt, unchanged);
        let mut old = seed.clone();
        old[125 * 512 + 511] = 1;
        assert!(fetched(&old, &bytes, &p, actual).is_err());
    }
}
