use super::*;
const ROOTS: usize = 1056;
const METADATA: usize = 1504;
const CONTENT: usize = 1672;
const CONTENT_BYTES: usize = 208;
const AUTH: usize = 2296;
const END: usize = AUTH + 3 * 112;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Content {
    pub object: Object,
    pub version: u64,
    pub app: [u8; 16],
    pub package: [u8; 32],
    pub build: [u8; 32],
    pub descriptor: [u8; 32],
    pub source: [u8; 32],
}
impl Content {
    fn valid(&self) -> bool {
        self.app == HELLO_APP
            && self.package == self.object.sha256()
            && ![self.package, self.build, self.descriptor, self.source].contains(&[0; 32])
            && !matches!(self.version, 0 | u64::MAX)
    }
}
/// Exact immutable signed authorization evidence for one retained member.
/// Current metadata may advance while this old local target remains bootable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub(super) root: Object,
    pub(super) targets: Object,
}
impl Authorization {
    pub fn root(self) -> Object {
        self.root
    }
    pub fn targets(self) -> Object {
        self.targets
    }
}
/// Syntax-only immutable-checkpoint record; it grants no trust or lifecycle
/// status. Only the authenticated cold-open path may construct ready state.
pub struct Record {
    pub(super) revision: u64,
    pub(super) replay: [u8; ev_release_trust::checkpoint::BYTES],
    pub(super) roots: [Option<Object>; MAX_ROOT_MATERIALS],
    pub(super) metadata: [Option<Object>; 3],
    pub(super) candidate: Option<Content>,
    pub(super) active: Option<Content>,
    pub(super) known_good: Option<Content>,
    pub(super) authorizations: [Option<Authorization>; 3],
}
fn word(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
fn put(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_le_bytes());
}
#[inline(never)]
fn object(b: &[u8]) -> Result<Object, Fault> {
    let o = Object::checked(word(b, 0), word(b, 16), b[24..56].try_into().unwrap())
        .map_err(|_| Fault::Checkpoint)?;
    if o.sectors() != word(b, 8) {
        return Err(Fault::Checkpoint);
    }
    Ok(o)
}
#[inline(never)]
fn encode_object(o: Object, b: &mut [u8]) {
    put(b, 0, o.start());
    put(b, 8, o.sectors());
    put(b, 16, o.length());
    b[24..56].copy_from_slice(&o.sha256());
}
#[inline(never)]
fn content(b: &[u8]) -> Result<Content, Fault> {
    let c = Content {
        object: object(b)?,
        version: word(b, 56),
        app: b[64..80].try_into().unwrap(),
        package: b[80..112].try_into().unwrap(),
        build: b[112..144].try_into().unwrap(),
        descriptor: b[144..176].try_into().unwrap(),
        source: b[176..208].try_into().unwrap(),
    };
    if !c.valid() {
        return Err(Fault::Checkpoint);
    }
    Ok(c)
}
#[inline(never)]
fn encode_content(c: Content, b: &mut [u8]) {
    encode_object(c.object, b);
    put(b, 56, c.version);
    b[64..80].copy_from_slice(&c.app);
    b[80..112].copy_from_slice(&c.package);
    b[112..144].copy_from_slice(&c.build);
    b[144..176].copy_from_slice(&c.descriptor);
    b[176..208].copy_from_slice(&c.source);
}
impl Record {
    pub fn authorization(&self, c: Content) -> Option<Authorization> {
        [self.candidate, self.active, self.known_good]
            .iter()
            .zip(self.authorizations)
            .find_map(|(v, a)| (*v == Some(c)).then_some(a).flatten())
    }
    pub fn root_count(&self) -> usize {
        self.roots.iter().flatten().count()
    }
    pub fn references(&self) -> impl Iterator<Item = Object> + '_ {
        self.roots
            .iter()
            .chain(self.metadata.iter())
            .copied()
            .flatten()
            .chain(
                self.authorizations
                    .iter()
                    .flatten()
                    .flat_map(|p| [p.root, p.targets]),
            )
            .chain(
                self.candidate
                    .iter()
                    .chain(self.active.iter())
                    .chain(self.known_good.iter())
                    .map(|c| c.object),
            )
    }
    pub fn validate(&self) -> Result<(), Fault> {
        let n = self.root_count();
        if matches!(self.revision, 0 | u64::MAX)
            || n == 0
            || self.roots[..n].iter().any(Option::is_none)
            || self.roots[n..].iter().any(Option::is_some)
            || self.metadata.iter().any(Option::is_some)
                && self.metadata.iter().any(Option::is_none)
            || self.candidate.is_some() && self.metadata[0].is_none()
            || self
                .candidate
                .iter()
                .chain(self.active.iter())
                .chain(self.known_good.iter())
                .any(|c| !c.valid())
        {
            return Err(Fault::Checkpoint);
        }
        let first = self.roots[0].ok_or(Fault::Checkpoint)?;
        if first.length() != ROM_ROOT.len() as u64 || first.sha256() != digest(ROM_ROOT) {
            return Err(Fault::Root);
        }
        for (i, c) in [self.candidate, self.active, self.known_good]
            .into_iter()
            .enumerate()
        {
            match (c, self.authorizations[i]) {
                (None, None) => (),
                (Some(_), Some(a))
                    if self.roots.contains(&Some(a.root))
                        && a.root.length() <= ROOT_BUFFER as u64
                        && a.targets.length() <= TARGET_BUFFER as u64 => {}
                _ => return Err(Fault::Checkpoint),
            }
        }
        if let Some(a) = self.authorizations[0]
            && (Some(a.root) != self.roots[self.root_count() - 1]
                || Some(a.targets) != self.metadata[0])
        {
            return Err(Fault::Metadata);
        }
        for (i, a) in self.references().enumerate() {
            for b in self.references().skip(i + 1) {
                if a != b
                    && a.start() < b.start() + b.sectors()
                    && b.start() < a.start() + a.sectors()
                {
                    return Err(Fault::Checkpoint);
                }
            }
        }
        Ok(())
    }
    pub fn encode(&self, out: &mut [u8; CHECKPOINT_BYTES]) -> Result<(), Fault> {
        self.validate()?;
        out.fill(0);
        out[..8].copy_from_slice(b"EVACQ002");
        out[8] = 2;
        out[10] = self.root_count() as u8;
        out[11] = if self.metadata[0].is_some() { 7 } else { 0 };
        put(out, 16, self.revision);
        out[32..1056].copy_from_slice(&self.replay);
        for (i, o) in self.roots.iter().enumerate() {
            if let Some(o) = o {
                encode_object(*o, &mut out[ROOTS + i * 56..ROOTS + (i + 1) * 56]);
            }
        }
        for (i, o) in self.metadata.iter().enumerate() {
            if let Some(o) = o {
                encode_object(*o, &mut out[METADATA + i * 56..METADATA + (i + 1) * 56]);
            }
        }
        for (i, c) in [self.candidate, self.active, self.known_good]
            .into_iter()
            .enumerate()
        {
            if let Some(c) = c {
                out[9] |= 1 << i;
                encode_content(
                    c,
                    &mut out[CONTENT + i * CONTENT_BYTES..CONTENT + (i + 1) * CONTENT_BYTES],
                );
            }
        }
        for (i, a) in self.authorizations.iter().enumerate() {
            if let Some(a) = a {
                let row = &mut out[AUTH + i * 112..AUTH + (i + 1) * 112];
                encode_object(a.root, &mut row[..56]);
                encode_object(a.targets, &mut row[56..]);
            }
        }
        Ok(())
    }
    pub fn decode(b: &[u8; CHECKPOINT_BYTES]) -> Result<Self, Fault> {
        if &b[..8] != b"EVACQ002"
            || b[8] != 2
            || b[9] & !7 != 0
            || !(1..=MAX_ROOT_MATERIALS).contains(&(b[10] as usize))
            || !matches!(b[11], 0 | 7)
            || b[12..16]
                .iter()
                .chain(b[24..32].iter())
                .chain(b[END..].iter())
                .any(|x| *x != 0)
        {
            return Err(Fault::Checkpoint);
        }
        let mut roots = [None; MAX_ROOT_MATERIALS];
        for (i, o) in roots.iter_mut().enumerate() {
            let row = &b[ROOTS + i * 56..ROOTS + (i + 1) * 56];
            if i < usize::from(b[10]) {
                *o = Some(object(row)?);
            } else if row.iter().any(|x| *x != 0) {
                return Err(Fault::Checkpoint);
            }
        }
        let mut metadata = [None; 3];
        for (i, o) in metadata.iter_mut().enumerate() {
            let row = &b[METADATA + i * 56..METADATA + (i + 1) * 56];
            if b[11] != 0 {
                *o = Some(object(row)?);
            } else if row.iter().any(|x| *x != 0) {
                return Err(Fault::Checkpoint);
            }
        }
        let mut values = [None; 3];
        for (i, o) in values.iter_mut().enumerate() {
            let row = &b[CONTENT + i * CONTENT_BYTES..CONTENT + (i + 1) * CONTENT_BYTES];
            if b[9] & (1 << i) != 0 {
                *o = Some(content(row)?);
            } else if row.iter().any(|x| *x != 0) {
                return Err(Fault::Checkpoint);
            }
        }
        let mut authorizations = [None; 3];
        for (i, a) in authorizations.iter_mut().enumerate() {
            let row = &b[AUTH + i * 112..AUTH + (i + 1) * 112];
            if values[i].is_some() {
                *a = Some(Authorization {
                    root: object(&row[..56])?,
                    targets: object(&row[56..])?,
                })
            } else if row.iter().any(|n| *n != 0) {
                return Err(Fault::Checkpoint);
            }
        }
        let result = Self {
            revision: word(b, 16),
            replay: b[32..1056].try_into().unwrap(),
            roots,
            metadata,
            candidate: values[0],
            active: values[1],
            known_good: values[2],
            authorizations,
        };
        result.validate()?;
        Ok(result)
    }
}
