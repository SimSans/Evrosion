use super::*;
const MAGIC: &[u8; 8] = b"EVSTORE1";
fn put64(b: &mut [u8], i: usize, value: u64) {
    b[i..i + 8].copy_from_slice(&value.to_le_bytes());
}
fn get64(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
fn put16(b: &mut [u8], i: usize, value: u16) {
    b[i..i + 2].copy_from_slice(&value.to_le_bytes());
}
fn get16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(b[i..i + 2].try_into().unwrap())
}
fn hash_at(b: &[u8], i: usize) -> Digest {
    b[i..i + 32].try_into().unwrap()
}
fn empty(b: &[u8]) -> bool {
    b.iter().all(|&v| v == 0)
}
fn header(kind: u8, sequence: u64, related: u64, len: usize) -> Sector {
    let mut b = [0; SECTOR_BYTES];
    b[..8].copy_from_slice(MAGIC);
    put16(&mut b, 8, FORMAT_VERSION);
    b[10] = kind;
    put64(&mut b, 16, sequence);
    put64(&mut b, 24, related);
    put16(&mut b, 32, len as u16);
    b
}
fn seal(mut b: Sector) -> Sector {
    let hash = digest(&b[..480]);
    b[480..].copy_from_slice(&hash);
    b
}
fn checked(b: &Sector, kind: u8) -> Option<(u64, u64, &[u8])> {
    if &b[..8] != MAGIC
        || get16(b, 8) != FORMAT_VERSION
        || b[10] != kind
        || !empty(&b[11..16])
        || !empty(&b[34..64])
        || digest(&b[..480]) != b[480..]
    {
        return None;
    }
    let len = usize::from(get16(b, 32));
    if len > 416 || !empty(&b[64 + len..480]) {
        return None;
    }
    Some((get64(b, 16), get64(b, 24), &b[64..64 + len]))
}
pub(super) fn unsupported_format(b: &Sector) -> bool {
    &b[..8] == MAGIC && get16(b, 8) != FORMAT_VERSION
}
pub(super) fn manifest(value: &GenerationManifest) -> [u8; MANIFEST_BYTES] {
    let mut b = [0; MANIFEST_BYTES];
    b[..8].copy_from_slice(b"EVGEN001");
    put16(&mut b, 8, 1);
    put16(&mut b, 10, value.health_version);
    b[12..16].copy_from_slice(&value.required_checks.to_le_bytes());
    put64(&mut b, 16, value.generation.get());
    b[24..56].copy_from_slice(&value.cohort);
    b[56..88].copy_from_slice(&value.supervisor_image);
    b[88..120].copy_from_slice(&value.abi);
    b[120..152].copy_from_slice(&value.health_contract);
    b
}
pub(super) fn decode_manifest(b: &[u8]) -> Option<GenerationManifest> {
    if b.len() != MANIFEST_BYTES || &b[..8] != b"EVGEN001" || get16(b, 8) != 1 || !empty(&b[152..])
    {
        return None;
    }
    let value = GenerationManifest {
        generation: GenerationId::new(get64(b, 16))?,
        cohort: hash_at(b, 24),
        supervisor_image: hash_at(b, 56),
        abi: hash_at(b, 88),
        health_contract: hash_at(b, 120),
        health_version: get16(b, 10),
        required_checks: u32::from_le_bytes(b[12..16].try_into().unwrap()),
    };
    value.valid().then_some(value)
}
pub(super) fn data(kind: u8, id: u64, related: u64, bytes: &[u8]) -> Sector {
    let mut b = header(kind, id, related, bytes.len());
    b[64..64 + bytes.len()].copy_from_slice(bytes);
    seal(b)
}
pub(super) fn decode_data(b: &Sector, kind: u8, id: u64, related: u64) -> Option<&[u8]> {
    let (found, peer, body) = checked(b, kind)?;
    if found != id || peer != related || body.len() > PAYLOAD_BYTES {
        return None;
    }
    Some(body)
}
fn put_ref(b: &mut [u8], i: usize, g: GenerationRef) {
    put64(b, i, g.id);
    b[i + 8..i + 40].copy_from_slice(&g.digest);
    b[i + 40..i + 72].copy_from_slice(&g.image);
    put16(b, i + 72, g.len);
}
fn get_ref(b: &[u8], i: usize) -> Option<GenerationRef> {
    if !empty(&b[i + 74..i + 80]) {
        return None;
    }
    let g = GenerationRef {
        id: get64(b, i),
        digest: hash_at(b, i + 8),
        image: hash_at(b, i + 40),
        len: get16(b, i + 72),
    };
    if g.id == 0 {
        return (g == GenerationRef::EMPTY).then_some(g);
    }
    (GenerationId::new(g.id).is_some()
        && g.digest != ZERO
        && g.image != ZERO
        && usize::from(g.len) == MANIFEST_BYTES)
        .then_some(g)
}
pub(super) fn root(value: &Root) -> Sector {
    let mut b = header(ROOT_KIND, value.sequence, value.last_operation, 384);
    let p = &mut b[64..448];
    p[0] = value.active;
    p[1] = value.known_good;
    p[2] = value.staged;
    p[3] = value.phase;
    p[4] = value.attempts;
    p[5] = value.max_attempts;
    p[6] = value.user_slot;
    p[7] = u8::from(value.boot_pending);
    put64(p, 8, value.highest_generation);
    put_ref(p, 16, value.generations[0]);
    put_ref(p, 96, value.generations[1]);
    put16(p, 176, value.user_len);
    put64(p, 184, value.user_revision);
    p[192..224].copy_from_slice(&value.user_digest);
    p[224..256].copy_from_slice(&value.admitted_stamp);
    put64(p, 256, value.boot_serial);
    put64(p, 264, value.admitted_serial);
    if let Some(failure) = value.last_failure {
        p[272] = 1;
        p[273] = match failure.reason {
            LastFailureReason::ProcessFault => 1,
            LastFailureReason::MissingProgress => 2,
            LastFailureReason::StorageFailure => 3,
            LastFailureReason::AttemptBudgetExhausted => 4,
        };
        p[274] = failure.attempts;
        p[275] = u8::from(failure.process_stamp.is_some());
        put64(p, 280, failure.generation.get());
        put64(p, 288, failure.boot_serial);
        put64(p, 296, failure.operation.get());
        put64(p, 304, failure.sequence);
        p[312..344].copy_from_slice(&failure.supervisor_image);
        if let Some(stamp) = failure.process_stamp {
            p[344..376].copy_from_slice(&stamp);
        }
    }
    seal(b)
}
pub(super) fn decode_root(b: &Sector) -> Option<Root> {
    let (sequence, last_operation, p) = checked(b, ROOT_KIND)?;
    if p.len() != 384
        || sequence == 0
        || last_operation.checked_add(1) != Some(sequence)
        || p[7] > 1
        || !empty(&p[178..184])
    {
        return None;
    }
    let value = Root {
        sequence,
        last_operation,
        active: p[0],
        known_good: p[1],
        staged: p[2],
        phase: p[3],
        attempts: p[4],
        max_attempts: p[5],
        user_slot: p[6],
        highest_generation: get64(p, 8),
        generations: [get_ref(p, 16)?, get_ref(p, 96)?],
        user_len: get16(p, 176),
        user_revision: get64(p, 184),
        user_digest: hash_at(p, 192),
        admitted_stamp: hash_at(p, 224),
        boot_serial: get64(p, 256),
        admitted_serial: get64(p, 264),
        boot_pending: p[7] == 1,
        last_failure: decode_failure(p)?,
    };
    if value.active > 1
        || value.known_good > 2
        || value.staged > 2
        || value.phase > 3
        || value.attempts > value.max_attempts
        || BootPolicy::new(value.max_attempts).is_none()
        || value.user_slot > 1
        || usize::from(value.user_len) > PAYLOAD_BYTES
        || value.user_revision == 0
        || value.user_digest == ZERO
    {
        return None;
    }
    if value.generations[value.active as usize].id == 0
        || (value.known_good < 2 && value.generations[value.known_good as usize].id == 0)
        || value
            .generations
            .iter()
            .any(|g| g.id > value.highest_generation)
    {
        return None;
    }
    if value.generations[0].id != 0 && value.generations[0].id == value.generations[1].id {
        return None;
    }
    match value.phase {
        0 => {
            if value.active != value.known_good
                || value.staged != 0
                || (!value.boot_pending && value.attempts != 0)
            {
                return None;
            }
        }
        1 => {
            if value.active != value.known_good
                || value.staged == 0
                || value.staged - 1 == value.active
                || value.attempts != 0
                || value.boot_pending
            {
                return None;
            }
        }
        2 => {
            if value.staged == 0
                || value.active != value.staged - 1
                || value.active == value.known_good
            {
                return None;
            }
        }
        3 => {
            if value.staged != 0 || value.attempts != 0 || value.boot_pending {
                return None;
            }
        }
        _ => return None,
    }
    if value.boot_pending && (value.boot_serial == 0 || value.attempts == 0) {
        return None;
    }
    if !value.boot_pending && value.attempts != 0 {
        return None;
    }
    if value.staged != 0 && value.generations[(value.staged - 1) as usize].id == 0 {
        return None;
    }
    if value.admitted_stamp == ZERO {
        if value.admitted_serial != 0 {
            return None;
        }
    } else if !matches!(value.phase, 0 | 2)
        || !value.boot_pending
        || value.attempts == 0
        || value.admitted_serial != value.boot_serial
        || value.boot_serial == 0
    {
        return None;
    }
    if let Some(failure) = value.last_failure
        && (failure.generation.get() > value.highest_generation
            || failure.boot_serial > value.boot_serial
            || failure.attempts > value.max_attempts
            || failure.operation.get() > value.last_operation
            || failure.sequence > value.sequence
            || (failure.reason == LastFailureReason::AttemptBudgetExhausted
                && failure.attempts != value.max_attempts)
            || value.generations.iter().any(|reference| {
                reference.id == failure.generation.get()
                    && reference.image != failure.supervisor_image
            }))
    {
        return None;
    }
    Some(value)
}
fn decode_failure(p: &[u8]) -> Option<Option<LastFailure>> {
    if p[272] == 0 {
        return empty(&p[272..384]).then_some(None);
    }
    if p[272] != 1 || p[275] > 1 || !empty(&p[276..280]) || !empty(&p[376..384]) {
        return None;
    }
    let reason = match p[273] {
        1 => LastFailureReason::ProcessFault,
        2 => LastFailureReason::MissingProgress,
        3 => LastFailureReason::StorageFailure,
        4 => LastFailureReason::AttemptBudgetExhausted,
        _ => return None,
    };
    let raw_stamp = hash_at(p, 344);
    let process_stamp = if p[275] == 1 {
        if raw_stamp == ZERO {
            return None;
        }
        Some(raw_stamp)
    } else {
        if raw_stamp != ZERO || reason != LastFailureReason::AttemptBudgetExhausted {
            return None;
        }
        None
    };
    let failure = LastFailure {
        generation: GenerationId::new(get64(p, 280))?,
        boot_serial: get64(p, 288),
        attempts: p[274],
        reason,
        supervisor_image: hash_at(p, 312),
        process_stamp,
        operation: OperationId::new(get64(p, 296))?,
        sequence: get64(p, 304),
    };
    if failure.boot_serial == 0
        || failure.attempts == 0
        || failure.supervisor_image == ZERO
        || failure.operation.get().checked_add(1) != Some(failure.sequence)
    {
        return None;
    }
    Some(Some(failure))
}
fn encode_admission(report: AdmissionReport, out: &mut [u8]) {
    out[..32].copy_from_slice(&report.process_stamp);
    out[32..64].copy_from_slice(&report.cohort);
    out[64..96].copy_from_slice(&report.supervisor_image);
    out[96..128].copy_from_slice(&report.abi);
    out[128..160].copy_from_slice(&report.health_contract);
    put16(out, 160, report.health_version);
}
pub(super) fn decode_admission(op: &Operation) -> Option<AdmissionReport> {
    if !matches!(op.kind, 4 | 5) || usize::from(op.len) != if op.kind == 4 { 162 } else { 198 } {
        return None;
    }
    Some(AdmissionReport {
        generation: GenerationId::new(op.generation)?,
        boot_serial: op.boot_serial,
        process_stamp: hash_at(&op.body, 0),
        cohort: hash_at(&op.body, 32),
        supervisor_image: hash_at(&op.body, 64),
        abi: hash_at(&op.body, 96),
        health_contract: hash_at(&op.body, 128),
        health_version: get16(&op.body, 160),
    })
}
pub(super) fn health_details(op: &Operation) -> Option<(u32, Digest)> {
    if op.kind != 5 || op.len != 198 {
        return None;
    }
    Some((
        u32::from_le_bytes(op.body[194..198].try_into().unwrap()),
        hash_at(&op.body, 162),
    ))
}
fn fingerprint(op: &Operation) -> Digest {
    let mut body = [0; 280];
    body[0] = op.kind;
    body[1] = op.health;
    put16(&mut body, 2, op.len);
    put64(&mut body, 8, op.generation);
    put64(&mut body, 16, op.boot_serial);
    body[24..].copy_from_slice(&op.body);
    digest(&body)
}
pub(super) fn operation<E>(request: Request<'_>) -> Result<Operation, Error<E>> {
    let mut op = Operation {
        kind: 0,
        health: 0,
        generation: 0,
        boot_serial: 0,
        len: 0,
        body: [0; PAYLOAD_BYTES],
        fingerprint: ZERO,
    };
    match request {
        Request::Stage(value) => {
            if !value.valid() {
                return Err(Error::InvalidRequest);
            }
            op.kind = 1;
            op.generation = value.generation.get();
            op.len = MANIFEST_BYTES as u16;
            op.body[..MANIFEST_BYTES].copy_from_slice(&manifest(value));
        }
        Request::Activate(id) => {
            op.kind = 2;
            op.generation = id.get();
        }
        Request::BeginBoot(id) => {
            op.kind = 3;
            op.generation = id.get();
        }
        Request::Admission(report) => {
            op.kind = 4;
            op.generation = report.generation.get();
            op.boot_serial = report.boot_serial;
            op.len = 162;
            encode_admission(report, &mut op.body);
        }
        Request::Health(report) => {
            op.kind = 5;
            op.health = match report.outcome {
                HealthOutcome::CriticalPassed => 1,
                HealthOutcome::ProcessFault => 2,
                HealthOutcome::MissingProgress => 3,
                HealthOutcome::StorageFailure => 4,
            };
            op.generation = report.admitted.generation.get();
            op.boot_serial = report.admitted.boot_serial;
            op.len = 198;
            encode_admission(report.admitted, &mut op.body);
            op.body[162..194].copy_from_slice(&report.storage_probe);
            op.body[194..198].copy_from_slice(&report.observed_checks.to_le_bytes());
        }
        Request::WriteMutable { object, bytes } => {
            if object.get() != USER_OBJECT {
                return Err(Error::UnknownObject);
            }
            if bytes.len() > PAYLOAD_BYTES {
                return Err(Error::Capacity);
            }
            op.kind = 6;
            op.len = bytes.len() as u16;
            op.body[..bytes.len()].copy_from_slice(bytes);
        }
        Request::SelectKnownGood => op.kind = 7,
    }
    op.fingerprint = fingerprint(&op);
    Ok(op)
}
pub(super) fn journal(id: u64, base: u64, op: &Operation) -> Sector {
    let mut b = header(OP_KIND, id, base, 312);
    let p = &mut b[64..376];
    p[0] = op.kind;
    p[1] = op.health;
    put16(p, 2, op.len);
    put64(p, 8, op.generation);
    put64(p, 16, op.boot_serial);
    p[24..56].copy_from_slice(&op.fingerprint);
    p[56..].copy_from_slice(&op.body);
    seal(b)
}
pub(super) fn decode_operation(b: &Sector) -> Option<(u64, u64, Operation)> {
    let (id, base, p) = checked(b, OP_KIND)?;
    if OperationId::new(id).is_none() || base == 0 || p.len() != 312 || !empty(&p[4..8]) {
        return None;
    }
    let op = Operation {
        kind: p[0],
        health: p[1],
        len: get16(p, 2),
        generation: get64(p, 8),
        boot_serial: get64(p, 16),
        fingerprint: hash_at(p, 24),
        body: p[56..312].try_into().unwrap(),
    };
    if usize::from(op.len) > PAYLOAD_BYTES
        || !empty(&op.body[usize::from(op.len)..])
        || fingerprint(&op) != op.fingerprint
    {
        return None;
    }
    match op.kind {
        1 => {
            let m = decode_manifest(&op.body[..usize::from(op.len)])?;
            if m.generation.get() != op.generation || op.health != 0 || op.boot_serial != 0 {
                return None;
            }
        }
        2 | 3 => {
            if GenerationId::new(op.generation).is_none()
                || op.len != 0
                || op.health != 0
                || op.boot_serial != 0
            {
                return None;
            }
        }
        4 => {
            if decode_admission(&op)?.process_stamp == ZERO || op.boot_serial == 0 || op.health != 0
            {
                return None;
            }
        }
        5 => {
            if decode_admission(&op)?.process_stamp == ZERO
                || op.boot_serial == 0
                || !(1..=4).contains(&op.health)
            {
                return None;
            }
        }
        6 => {
            if op.generation != 0 || op.boot_serial != 0 || op.health != 0 {
                return None;
            }
        }
        7 => {
            if op.generation != 0 || op.boot_serial != 0 || op.health != 0 || op.len != 0 {
                return None;
            }
        }
        _ => return None,
    }
    Some((id, base, op))
}
