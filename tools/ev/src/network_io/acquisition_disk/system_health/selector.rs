//! Read-only next-mode projection from the same authenticated retained media.
//! Install as a child of acquisition_disk::system_health to share its verifier.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Selection {
    Unformatted,
    Committed {
        selected: GenerationManifest,
        known_good: Option<GenerationManifest>,
    },
    Recovery {
        known_good: Option<GenerationManifest>,
    },
}

pub(super) fn stored_package<'a>(
    store: acq::Store<Media<'a>>,
    content: acq::Content,
) -> Result<(acq::Store<Media<'a>>, Vec<u8>)> {
    if content.object.length() > 262144 || content.object.length() == 0 {
        return Err("retained boot package exceeds declared bound".into());
    }
    let mut reader = store
        .begin_read(content.object, TransferCut::new(1, CUT).unwrap(), 1)
        .map_err(|_| "retained boot package reader")?;
    let mut bytes = Vec::with_capacity(content.object.length() as usize);
    let mut chunk = [0; 4096];
    while reader.remaining() != 0 {
        let n = reader
            .read_chunk(&mut chunk, 1)
            .map_err(|_| "retained boot package read/hash")?;
        if n == 0 || bytes.len().checked_add(n).is_none_or(|n| n > 262144) {
            return Err("retained boot package read bound".into());
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    let result = reader
        .finish()
        .map_err(|_| "retained boot package full hash/padding")?;
    if result.object != content.object || hash(&bytes) != content.package {
        return Err("retained boot package full identity differs".into());
    }
    Ok((result.store, bytes))
}
pub(crate) fn observe(bytes: &[u8], banks: &Packages<'_>) -> Result<Selection> {
    shape(bytes)?;
    if !banks.is_network() {
        return Err("retained boot selector requires exact V4 context".into());
    }
    let content_blank = bytes
        .as_chunks::<512>()
        .0
        .iter()
        .enumerate()
        .filter(|(sector, _)| content_sector(*sector))
        .all(|(_, b)| b.iter().all(|v| *v == 0));
    // Refuse v1 and damaged signed content even if System has not yet been
    // initialized. Entirely blank content is allowed only as genuinely blank.
    let mut content = if content_blank {
        None
    } else {
        Some(cold(bytes)?)
    };
    if let Some(mut store) = content.take() {
        let snapshot = store
            .snapshot()
            .ok_or("retained authenticated snapshot absent")?;
        let members = [
            snapshot.candidate(),
            snapshot.active(),
            snapshot.known_good(),
        ];
        for (i, member) in members.into_iter().enumerate() {
            if let Some(member) = member
                && !members[..i].contains(&Some(member))
            {
                let (next, artifact) = stored_package(store, member)?;
                store = next;
                manifest(banks, member, &artifact)?;
            }
        }
        content = Some(store);
    }
    let mut media = Media {
        bytes,
        reads: 0,
        writes: 0,
    };
    let mut system = match Store::open_downloaded_v2(media.region(Region::System), CUT) {
        Ok(system) => system,
        Err(r) if matches!(r.error, ev_store::Error::Unformatted) => {
            let first = Region::System.physical_start() as usize * 512;
            if bytes[first..first + ev_store::REQUIRED_SECTORS as usize * 512]
                .iter()
                .any(|v| *v != 0)
            {
                return Err(
                    "System unformatted result conflicts with retained nonblank bytes".into(),
                );
            }
            return Ok(Selection::Unformatted);
        }
        Err(r) => {
            return Err(format!(
                "retained System selector fenced without repair: {:?}",
                r.error
            ));
        }
    };
    let selected = match system.selected_manifest(CUT) {
        Ok(m) => Some(m),
        Err(ev_store::Error::RecoveryRequired) => None,
        Err(e) => return Err(format!("retained System selected manifest: {e:?}")),
    };
    let known_good = system
        .known_good_manifest(CUT)
        .map_err(|e| format!("retained System KnownGood manifest: {e:?}"))?;
    let _ = system;
    let mut store = content
        .take()
        .ok_or("committed System has no authenticated content namespace")?;
    for target in [selected, known_good].into_iter().flatten() {
        let s = store
            .snapshot()
            .ok_or("retained boot authenticated snapshot absent")?;
        let member = [s.candidate(), s.active(), s.known_good()]
            .into_iter()
            .flatten()
            .find(|c| c.version == target.generation.get())
            .ok_or("retained System member absent")?;
        let (next, bytes) = stored_package(store, member)?;
        store = next;
        if manifest(banks, member, &bytes)? != target {
            return Err("retained System incompatible with source-bound protected boot set".into());
        }
    }
    if media.writes != 0 || store.into_arena().into_backend().writes != 0 {
        return Err("retained boot selector attempted mutation/repair".into());
    }
    Ok(match selected {
        Some(selected) => Selection::Committed {
            selected,
            known_good,
        },
        None => Selection::Recovery { known_good },
    })
}

/// Authenticated durable floors are observations for fresh authoring only.
/// They never grant the consumer permission to accept metadata or execute it.
pub(crate) fn author_version(bytes: &[u8]) -> Result<Option<u64>> {
    shape(bytes)?;
    let blank = bytes
        .as_chunks::<512>()
        .0
        .iter()
        .enumerate()
        .filter(|(sector, _)| content_sector(*sector))
        .all(|(_, b)| b.iter().all(|v| *v == 0));
    if blank {
        return Ok(Some(1));
    }
    let store = cold(bytes)?;
    let snapshot = store
        .snapshot()
        .ok_or("retained author replay snapshot absent")?;
    if snapshot
        .replay()
        .targets()
        .iter()
        .flatten()
        .any(|floor| floor.version > 2)
    {
        return Ok(None);
    }
    let maximum = snapshot
        .replay()
        .roles()
        .iter()
        .flatten()
        .map(|role| role.version)
        .max()
        .unwrap_or(0);
    let next = maximum
        .checked_add(1)
        .filter(|v| *v != u64::MAX)
        .ok_or("retained metadata role version exhausted")?;
    Ok(Some(next))
}

/// A live observation gate only. Full authentication remains in observe();
/// this additionally requires the completed local content KnownGood join.
/// A missing join is pending, never permission to repair or retry guest IO.
pub(crate) fn joined_known_good(
    bytes: &[u8],
    banks: &Packages<'_>,
    generation: u64,
) -> Result<Option<GenerationManifest>> {
    let Selection::Committed {
        selected,
        known_good: Some(known_good),
    } = observe(bytes, banks)?
    else {
        return Ok(None);
    };
    if selected != known_good || selected.generation.get() != generation {
        return Ok(None);
    }
    let content = cold(bytes)?;
    let snapshot = content
        .snapshot()
        .ok_or("owner cold authenticated snapshot absent")?;
    let Some(active) = snapshot.active() else {
        return Ok(None);
    };
    if active.version != generation
        || snapshot.candidate() != Some(active)
        || snapshot.known_good() != Some(active)
    {
        return Ok(None);
    }
    Ok(Some(selected))
}
