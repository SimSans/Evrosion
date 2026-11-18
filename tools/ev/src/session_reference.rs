// SPDX-License-Identifier: GPL-3.0-only
//! Host-only comparison with actual retained scanout and read-only Store bytes.
//! These references never replace guest pixels, acknowledge a guest operation,
//! create input authority, repair a volume or establish human consent.
use crate::{
    build::Result,
    desktop_protocol::{Producer, Step, StepKind},
    qmp::Ppm,
    storage,
};
use ev_graphics::{
    Color, HEIGHT, Pixels, WIDTH,
    composition::{cursor_pixel, session_app_sample},
    session::View,
    shell::Screen,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Buffer(Vec<Color>);
impl Pixels for Buffer {
    fn dimensions(&self) -> (usize, usize) {
        (WIDTH, HEIGHT)
    }
    fn write(
        &mut self,
        x: usize,
        y: usize,
        color: Color,
    ) -> core::result::Result<(), ev_graphics::Error> {
        if x >= WIDTH || y >= HEIGHT {
            return Err(ev_graphics::Error::Bounds);
        }
        self.0[y * WIDTH + x] = color;
        Ok(())
    }
}
pub(crate) struct Reference {
    pixels: Vec<Color>,
    shell: Vec<Color>,
    app: Option<Vec<Color>>,
}
impl Reference {
    pub(crate) fn document(
        screen: Screen,
        app: Option<ev_userspace_contract::document::Snapshot>,
        access: ev_userspace_contract::document::Access,
        cursor: Option<(u16, u8)>,
    ) -> Result<Self> {
        let mut shell = Buffer(vec![Color(0); WIDTH * HEIGHT]);
        ev_graphics::shell::render_session(&mut shell, screen)
            .map_err(|e| format!("document Shell reference: {e:?}"))?;
        if matches!(screen, Screen::Picker { .. }) {
            ev_graphics::shell::document_intent(&mut shell, screen, access)
                .map_err(|e| format!("document intent reference: {e:?}"))?;
        }
        let shell_surface = shell.0.clone();
        let app = if let Some(view) = app {
            let mut surface = Buffer(vec![Color(0); WIDTH * HEIGHT]);
            ev_graphics::document::render(&mut surface, &view)
                .map_err(|e| format!("document reference: {e:?}"))?;
            for y in 0..HEIGHT {
                for x in 0..WIDTH {
                    if let Some((sx, sy)) = session_app_sample(x, y) {
                        shell.0[y * WIDTH + x] = surface.0[sy * WIDTH + sx];
                    }
                }
            }
            Some(surface.0)
        } else {
            None
        };
        if let Some((x, y)) = cursor {
            for py in 0..HEIGHT {
                for px in 0..WIDTH {
                    if let Some(color) = px
                        .checked_sub(usize::from(x))
                        .zip(py.checked_sub(usize::from(y)))
                        .and_then(|(dx, dy)| cursor_pixel(dx, dy))
                    {
                        shell.0[py * WIDTH + px] = color;
                    }
                }
            }
        }
        Ok(Self {
            pixels: shell.0,
            shell: shell_surface,
            app,
        })
    }
    pub(crate) fn new(
        screen: Screen,
        app: Option<View<'_>>,
        cursor: Option<(u16, u8)>,
    ) -> Result<Self> {
        Self::render(screen, app, cursor, false)
    }
    pub(crate) fn owner(
        screen: Screen,
        app: Option<View<'_>>,
        cursor: Option<(u16, u8)>,
    ) -> Result<Self> {
        Self::render(screen, app, cursor, true)
    }
    fn render(
        screen: Screen,
        app: Option<View<'_>>,
        cursor: Option<(u16, u8)>,
        owner: bool,
    ) -> Result<Self> {
        if (screen == Screen::AppRunning) != app.is_some() {
            return Err("session reference visibility differs".into());
        }
        let mut shell = Buffer(vec![Color(0); WIDTH * HEIGHT]);
        ev_graphics::shell::render_session(&mut shell, screen)
            .map_err(|e| format!("session Shell reference: {e:?}"))?;
        if owner && screen == Screen::Home {
            ev_graphics::connection::entry(&mut shell)
                .map_err(|e| format!("owner entry reference: {e:?}"))?;
        }
        let shell_surface = shell.0.clone();
        let app = if let Some(view) = app {
            let mut surface = Buffer(vec![Color(0); WIDTH * HEIGHT]);
            ev_graphics::session::render(&mut surface, view)
                .map_err(|e| format!("session App reference: {e:?}"))?;
            for y in 0..HEIGHT {
                for x in 0..WIDTH {
                    if let Some((sx, sy)) = session_app_sample(x, y) {
                        shell.0[y * WIDTH + x] = surface.0[sy * WIDTH + sx];
                    }
                }
            }
            Some(surface.0)
        } else {
            None
        };
        if let Some((x, y)) = cursor {
            let (x, y) = (usize::from(x), usize::from(y));
            if x >= WIDTH || y >= HEIGHT {
                return Err("session cursor reference outside logical scanout".into());
            }
            for cy in 0..ev_graphics::composition::CURSOR_HEIGHT.min(HEIGHT - y) {
                for cx in 0..ev_graphics::composition::CURSOR_WIDTH.min(WIDTH - x) {
                    if let Some(color) = cursor_pixel(cx, cy) {
                        shell.0[(y + cy) * WIDTH + x + cx] = color;
                    }
                }
            }
        }
        Ok(Self {
            pixels: shell.0,
            shell: shell_surface,
            app,
        })
    }
    pub(crate) fn surface_hash(&self, producer: Producer, sequence: u64) -> Result<String> {
        let pixels = match producer {
            Producer::Shell => &self.shell,
            Producer::App => self.app.as_ref().ok_or("session App reference absent")?,
        };
        let mut h = Sha256::new();
        h.update(
            ev_graphics::SurfaceHeader { sequence }
                .encode()
                .map_err(|e| format!("session reference header: {e:?}"))?,
        );
        for pixel in pixels {
            h.update(pixel.0.to_le_bytes());
        }
        h.update(vec![
            0;
            ev_graphics::MAPPED_BYTES
                - ev_graphics::HEADER_BYTES
                - ev_graphics::PIXEL_BYTES
        ]);
        Ok(format!("{:x}", h.finalize()))
    }
    /// Readiness to inspect real scanout, not a substitute for pixel validation.
    /// An App may finish its own Present while a submitted picker is still the
    /// actual visible Shell surface. Never pause/capture that known interim UI.
    /// A candidate App frame must follow the latest actual Shell AppRunning
    /// Present and its same-incarnation protected Input barrier. Pixel checking
    /// remains independent and must never retry a cached earlier App frame.
    pub(crate) fn fresh_app_ready(
        &self,
        app: &Step,
        app_line: usize,
        shell: &Step,
        shell_line: usize,
        ui: &crate::session_io::ProbeUi,
    ) -> Result<bool> {
        Ok(app_line > shell_line
            && self.app_composition_ready(app, Some(shell))?
            && ui.ready(app.shell_process, shell.frame, shell_line))
    }
    pub(crate) fn app_composition_ready(&self, app: &Step, shell: Option<&Step>) -> Result<bool> {
        let Some(shell) = shell else { return Ok(false) };
        if app.producer != Producer::App
            || app.kind != StepKind::Frame
            || shell.producer != Producer::Shell
            || shell.kind != StepKind::Frame
            || app.app_process == 0
            || app.app_process != shell.app_process
            || app.shell_process != shell.shell_process
            || app.display_process != shell.display_process
            || app.grants != shell.grants
            || (app.width, app.height) != (shell.width, shell.height)
        {
            return Ok(false);
        }
        Ok(
            self.surface_hash(Producer::App, app.frame)? == app.surface_sha256
                && self.surface_hash(Producer::Shell, shell.frame)? == shell.surface_sha256,
        )
    }
    fn pixel(&self, x: usize, y: usize, width: usize, height: usize) -> [u8; 3] {
        let left = (width - WIDTH * 2) / 2;
        let top = (height - HEIGHT * 2) / 2;
        if x >= left && x < left + WIDTH * 2 && y >= top && y < top + HEIGHT * 2 {
            self.pixels[(y - top) / 2 * WIDTH + (x - left) / 2].components()
        } else {
            ev_graphics::BACKGROUND.components()
        }
    }
    pub(crate) fn validate(&self, actual: &Ppm) -> Result<Value> {
        let (width, height) = actual.dimensions();
        if !(800..=2048).contains(&width) || !(600..=2048).contains(&height) {
            return Err("session scanout geometry unsupported".into());
        }
        let mut a = Sha256::new();
        let mut e = Sha256::new();
        for y in 0..height {
            for x in 0..width {
                let got = actual.pixel(x, y)?;
                let expected = self.pixel(x, y, width, height);
                a.update(got);
                e.update(expected);
                if got != expected {
                    return Err(format!(
                        "actual session scanout differs at({x},{y}): {got:?} != {expected:?}"
                    ));
                }
            }
        }
        Ok(
            json!({"width":width,"height":height,"pixels":width*height,"actual_rgb_sha256":format!("{:x}",a.finalize()),"expected_rgb_sha256":format!("{:x}",e.finalize()),"all_pixels_match":true}),
        )
    }
}

use ev_app_registry::note_data::{FORMAT_ABI, NoteDataEnvelope};
use ev_store::{GenerationId, GenerationManifest, ObjectId, Sector, SectorIo, Store};
use ev_userspace_contract::root_v2::native::catalogue::Catalogue;
const DEADLINE: u64 = 1;
const FIRST: usize = 112 * storage::SECTOR_BYTES;
const END: usize = 126 * storage::SECTOR_BYTES;
#[derive(Debug)]
enum ReadError {
    Bounds,
    Deadline,
    ReadOnly,
}
struct Snapshot<'a> {
    bytes: &'a [u8],
    start: usize,
    reads: u64,
    mutations: u64,
}
impl SectorIo for Snapshot<'_> {
    type Error = ReadError;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(
        &mut self,
        lba: u64,
        out: &mut Sector,
        deadline: u64,
    ) -> core::result::Result<(), ReadError> {
        if deadline != DEADLINE {
            return Err(ReadError::Deadline);
        }
        if lba >= self.sectors() {
            return Err(ReadError::Bounds);
        }
        let start = self.start * storage::SECTOR_BYTES + lba as usize * storage::SECTOR_BYTES;
        out.copy_from_slice(
            self.bytes
                .get(start..start + storage::SECTOR_BYTES)
                .ok_or(ReadError::Bounds)?,
        );
        self.reads += 1;
        Ok(())
    }
    fn write(&mut self, _: u64, _: &Sector, _: u64) -> core::result::Result<(), ReadError> {
        self.mutations += 1;
        Err(ReadError::ReadOnly)
    }
    fn flush(&mut self, _: u64) -> core::result::Result<(), ReadError> {
        self.mutations += 1;
        Err(ReadError::ReadOnly)
    }
}
fn creation(bytes: &[u8]) -> Result<(ev_zion::AppId, GenerationManifest)> {
    let catalogue =
        Catalogue::decode(bytes).map_err(|e| format!("session note retained catalogue: {e:?}"))?;
    if catalogue.base().app_id() != crate::native_package::HELLO_APP_ID
        || ev_root_supervisor::native_plan::session_layout_measurement(&catalogue)
            != catalogue.layout_measurement()
    {
        return Err("session note creation catalogue identity/layout differs".into());
    }
    let app = ev_zion::AppId::new(catalogue.base().app_id()).ok_or("session note AppId invalid")?;
    let mut h = Sha256::new();
    h.update(b"evrosion.session.app-note.namespace.v2\0");
    h.update(app.bytes());
    h.update(2u32.to_le_bytes());
    h.update(112u32.to_le_bytes());
    Ok((
        app,
        GenerationManifest {
            generation: GenerationId::new(1).unwrap(),
            cohort: h.finalize().into(),
            supervisor_image: catalogue.base().root_image(),
            abi: FORMAT_ABI,
            health_contract: Sha256::digest(b"note-namespace-creation-only; no health claim")
                .into(),
            health_version: 1,
            required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
        },
    ))
}
fn inspect(
    bytes: &[u8],
    app: ev_zion::AppId,
    expected: GenerationManifest,
) -> Result<(NoteDataEnvelope, Value)> {
    if bytes.len() != storage::DISK_BYTES {
        return Err("session note disk must be exact owned4MiB".into());
    }
    let mut store = Store::open(
        Snapshot {
            bytes,
            start: 112,
            reads: 0,
            mutations: 0,
        },
        DEADLINE,
    )
    .map_err(|r| {
        format!(
            "session note cannot open without observer repair: {:?}",
            r.error
        )
    })?;
    if store
        .selected_manifest(DEADLINE)
        .map_err(|e| format!("session note creation context: {e:?}"))?
        != expected
        || store
            .staged_manifest(DEADLINE)
            .map_err(|e| format!("session note staged context: {e:?}"))?
            != Some(expected)
        || store.known_good().is_some()
        || store
            .committed_boot_serial()
            .map_err(|e| format!("session note boot serial: {e:?}"))?
            != 0
        || store
            .highest_generation()
            .map_err(|e| format!("session note highest generation: {e:?}"))?
            != 1
        || store
            .last_failure()
            .map_err(|e| format!("session note failure metadata: {e:?}"))?
            .is_some()
        || !matches!(store.boot_plan(DEADLINE), Err(ev_store::Error::Phase))
    {
        return Err("session note exact creation metadata differs; no health inferred".into());
    }
    let mut raw = [0; 256];
    if store
        .read_mutable(ObjectId::user_data(), &mut raw, DEADLINE)
        .map_err(|e| format!("session note actual mutable read: {e:?}"))?
        != 256
    {
        return Err("session note body extent differs".into());
    }
    let note = NoteDataEnvelope::decode(&raw)
        .map_err(|e| format!("session note actual envelope: {e:?}"))?;
    let operation = store
        .next_operation()
        .map_err(|e| format!("session note operation: {e:?}"))?
        .get();
    if note.app() != app || note.counter().checked_add(1) != Some(operation) {
        return Err("session note actual App/revision/operation differs".into());
    }
    let device = store.into_device();
    if device.mutations != 0 {
        return Err("session note observer attempted mutation".into());
    }
    Ok((
        note,
        json!({"physical_sectors":[112,125],"mutable_object":1,"schema_epoch":2,"counter":note.counter(),"last_operation":operation-1,"next_operation":operation,"payload_sha256":format!("{:x}",Sha256::digest(raw)),"region_sha256":format!("{:x}",Sha256::digest(&bytes[FIRST..END])),"app_id":app.bytes(),"format_abi":FORMAT_ABI,"creation_root":expected.supervisor_image,"creation_cohort":expected.cohort,"generation":1,"known_good":null,"boot_serial":0,"reads":device.reads,"observer_mutations":device.mutations}),
    ))
}

struct Banks<'a> {
    bytes: [&'a [u8]; 2],
    packages: [ev_zion::Package<'a>; 2],
}
impl ev_app_registry::Packages for Banks<'_> {
    fn resolve(&self, digest: [u8; 32]) -> Option<&[u8]> {
        self.packages
            .iter()
            .position(|p| p.id().bytes() == digest)
            .map(|i| self.bytes[i])
    }
}
fn banks<'a>(catalogue: &Catalogue<'_>, bytes: [&'a [u8]; 2]) -> Result<Banks<'a>> {
    let packages = [
        ev_zion::Package::parse(bytes[0])
            .map_err(|e| format!("session actual package A: {e:?}"))?,
        ev_zion::Package::parse(bytes[1])
            .map_err(|e| format!("session actual package B: {e:?}"))?,
    ];
    for (i, p) in packages.iter().enumerate() {
        let (id, build, image, len) = if i == 0 {
            (
                catalogue.package_a(),
                catalogue.base().app_build(),
                catalogue
                    .base()
                    .images()
                    .nth(4)
                    .ok_or("session App A image absent")?
                    .image,
                catalogue.package_a_bytes(),
            )
        } else {
            (
                catalogue.package_b(),
                catalogue.package_b_build(),
                catalogue.app_b().image,
                catalogue.package_b_bytes(),
            )
        };
        if p.id().bytes() != id
            || p.app().build_id != build
            || p.app().claimed_app.bytes() != catalogue.base().app_id()
            || p.executable().digest != image
            || bytes[i].len() as u64 != len
            || p.app().data_schema.current != 1
            || p.app().data_schema.oldest_readable != 1
        {
            return Err(
                "session package bytes/build/image/App/schema differ from retained catalogue"
                    .into(),
            );
        }
        let [cpu, frames, processes, threads] =
            ev_userspace_contract::root_v2::catalogue::CHILD_LIMITS;
        let measured = ev_kernel::service::ServiceImage::verify(
            p.executable().bytes,
            image,
            ev_kernel::scheduler::Limits::new(cpu, frames, processes, threads),
            &crate::native_package::hello_roles(),
        )
        .map_err(|e| format!("session actual package ELF/role admission: {e:?}"))?;
        let descriptor = if i == 0 {
            catalogue.base().images().nth(4).unwrap().descriptor
        } else {
            catalogue.app_b().descriptor
        };
        if measured.digest() != descriptor {
            return Err("session package actual ELF descriptor differs from catalogue".into());
        }
        p.check_requirements(
            1,
            ev_userspace_contract::ABI,
            &ev_root_supervisor::native_plan::Contracts,
        )
        .map_err(|e| format!("session actual package requirements: {e:?}"))?;
        if !p
            .app()
            .capability_requests()
            .any(|r| r.required && r.capability == ev_zion::Capability::AppPrivateData)
            || ["ev.app.private-data", "ev.app.session-note"]
                .iter()
                .any(|name| {
                    !p.app().contracts().any(|r| {
                        r.name == *name && r.major == 1 && r.minimum_minor == 0 && r.features == 0
                    })
                })
        {
            return Err(
                "session actual package lacks explicit private-data/session-note requirements"
                    .into(),
            );
        }
    }
    if packages[0].id() == packages[1].id() {
        return Err("session A/B actual packages are ambiguous".into());
    }
    Ok(Banks { bytes, packages })
}
fn scalar_creation(catalogue: &Catalogue<'_>, start: u32) -> GenerationManifest {
    let mut h = Sha256::new();
    h.update(b"evrosion.native.store-format.v1\0");
    h.update(catalogue.bytes());
    h.update(start.to_le_bytes());
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: h.finalize().into(),
        supervisor_image: catalogue.base().root_image(),
        abi: ev_userspace_contract::root_v2::native::ABI,
        health_contract: Sha256::digest(b"format-context-only; no admitted health").into(),
        health_version: 1,
        required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
    }
}
fn read_created(
    bytes: &[u8],
    start: usize,
    expected: GenerationManifest,
    last: u64,
) -> Result<([u8; 256], Value)> {
    let mut store = Store::open(
        Snapshot {
            bytes,
            start,
            reads: 0,
            mutations: 0,
        },
        DEADLINE,
    )
    .map_err(|r| {
        format!(
            "session initial region{start} needs observer repair: {:?}",
            r.error
        )
    })?;
    if store
        .selected_manifest(DEADLINE)
        .map_err(|e| format!("session initial context: {e:?}"))?
        != expected
        || store
            .staged_manifest(DEADLINE)
            .map_err(|e| format!("session initial staged context: {e:?}"))?
            != Some(expected)
        || store.known_good().is_some()
        || store
            .committed_boot_serial()
            .map_err(|e| format!("session initial boot serial: {e:?}"))?
            != 0
        || store
            .highest_generation()
            .map_err(|e| format!("session initial highest generation: {e:?}"))?
            != 1
        || store
            .last_failure()
            .map_err(|e| format!("session initial failure: {e:?}"))?
            .is_some()
        || store
            .next_operation()
            .map_err(|e| format!("session initial operation: {e:?}"))?
            .get()
            != last
                .checked_add(1)
                .ok_or("session initial operation overflow")?
        || !matches!(store.boot_plan(DEADLINE), Err(ev_store::Error::Phase))
    {
        return Err("session initial Store context/operation differs; no health inferred".into());
    }
    let mut raw = [0; 256];
    if store
        .read_mutable(ObjectId::user_data(), &mut raw, DEADLINE)
        .map_err(|e| format!("session initial body: {e:?}"))?
        != 256
    {
        return Err("session initial mutable body length differs".into());
    }
    let device = store.into_device();
    if device.mutations != 0 {
        return Err("session initializer observer attempted mutation".into());
    }
    Ok((
        raw,
        json!({"physical_sectors":[start,start+13],"last_operation":last,"next_operation":last+1,"payload_sha256":format!("{:x}",Sha256::digest(raw)),"reads":device.reads,"observer_mutations":device.mutations,"creation_cohort":expected.cohort,"creation_root":expected.supervisor_image,"creation_abi":expected.abi,"known_good":null,"boot_serial":0}),
    ))
}
/// First explicit GUI launch may initialize only the three previously blank
/// namespaces. Validate their ACTUAL durable bodies and exact package references
/// before allowing the post-Saved snapshot to become the later Note baseline.
pub(crate) fn initialization(
    before: &[u8],
    baseline: &[u8],
    creation_catalogue: &[u8],
    packages: [&[u8]; 2],
) -> Result<Value> {
    if before.len() != storage::DISK_BYTES || baseline.len() != storage::DISK_BYTES {
        return Err("session initialization disk extent differs".into());
    }
    for start in [64, 80, 112] {
        if before[start * 512..(start + 14) * 512]
            .iter()
            .any(|b| *b != 0)
        {
            return Err(
                "session initial GUI install was not from three exactly blank namespaces".into(),
            );
        }
    }
    for (i, (old, new)) in before.iter().zip(baseline).enumerate() {
        let sector = i / 512;
        if !((64..78).contains(&sector)
            || (80..94).contains(&sector)
            || (112..126).contains(&sector))
            && old != new
        {
            return Err(format!(
                "session initial install changed unrelated sector{sector}"
            ));
        }
    }
    let (app, note_context) = creation(creation_catalogue)?;
    let catalogue = Catalogue::decode(creation_catalogue)
        .map_err(|e| format!("session initialization catalogue: {e:?}"))?;
    let banks = banks(&catalogue, packages)?;
    let (raw, mut registry) = read_created(baseline, 64, scalar_creation(&catalogue, 64), 2)?;
    let record = ev_zion::lifecycle::Record::decode(&raw)
        .map_err(|e| format!("session actual installed registry record: {e:?}"))?;
    let actual_a = banks.packages[0]
        .compatible(
            1,
            ev_userspace_contract::ABI,
            &ev_root_supervisor::native_plan::Contracts,
        )
        .map_err(|e| format!("session registry actual A compatibility: {e:?}"))?;
    if record.app() != app
        || record.revision() != 2
        || !record.installed()
        || record.data_epoch() != 1
        || record.active() != Some(ev_zion::lifecycle::VersionRef::from_package(&actual_a))
        || record.previous().is_some()
        || record.staged().is_some()
    {
        return Err(
            "session initial registry is not exact installed/active actual A revision2".into(),
        );
    }
    let resolver = ev_app_registry::Registry::open(
        Snapshot {
            bytes: baseline,
            start: 64,
            reads: 0,
            mutations: 0,
        },
        ev_app_registry::Policy {
            app,
            abi: ev_userspace_contract::ABI,
            platform: 1,
        },
        &banks,
        &ev_root_supervisor::native_plan::Contracts,
        DEADLINE,
    )
    .map_err(|r| format!("session actual cold registry resolver: {:?}", r.error))?;
    let head = resolver
        .expected()
        .map_err(|e| format!("session actual registry head: {e:?}"))?;
    let mut h = Sha256::new();
    h.update(b"evrosion.app-registry.head.v1\0");
    h.update(app.bytes());
    h.update(ev_userspace_contract::ABI);
    h.update(1u32.to_le_bytes());
    h.update(2u64.to_le_bytes());
    h.update(3u64.to_le_bytes());
    h.update(raw);
    let expected_head: [u8; 32] = h.finalize().into();
    if head.revision != 2 || head.base_head != expected_head {
        return Err("session actual registry canonical head differs".into());
    }
    let (device, _, pending) = resolver.into_parts();
    if pending.is_some() || device.mutations != 0 {
        return Err("session registry cold resolver has an unresolved mutation".into());
    }
    registry["revision"] = json!(2);
    registry["active_package"] = json!(banks.packages[0].id().bytes());
    registry["active_build"] = json!(banks.packages[0].app().build_id);
    registry["active_image"] = json!(banks.packages[0].executable().digest);
    registry["canonical_head"] = json!(head.base_head);
    registry["resolver_reads"] = json!(device.reads);
    let (raw, mut data) = read_created(baseline, 80, scalar_creation(&catalogue, 80), 0)?;
    let expected = ev_app_registry::app_data::AppDataEnvelope::initial(app, 1, 1001)
        .map_err(|e| format!("session initial scalar preparation: {e:?}"))?;
    if ev_app_registry::app_data::AppDataEnvelope::decode(&raw) != Ok(expected)
        || raw != expected.encode()
    {
        return Err(
            "session initial scalar v1 data differs from exact App/schema1/counter0/value1001"
                .into(),
        );
    }
    data["value"] = json!(1001);
    data["counter"] = json!(0);
    data["schema_epoch"] = json!(1);
    let (note, note_record) = inspect(baseline, app, note_context)?;
    if note.counter() != 0 || !note.note().is_empty() {
        return Err("session initial Note is not exact empty schema2/counter0".into());
    }
    Ok(
        json!({"schema":1,"passed":true,"scope":"Read-only exact original seed to actual first-Saved disk; only initially blank explicit namespace extents may initialize","registry":registry,"scalar_data":data,"note":note_record,"all_other_bytes_unchanged":true,"source_seed_sha256":format!("{:x}",Sha256::digest(before)),"initial_saved_disk_sha256":format!("{:x}",Sha256::digest(baseline))}),
    )
}
/// `before` is an actual paused post-initial-Saved baseline, not a blank seed.
/// The parent separately validates initial bundled install. This slice permits
/// ONLY the one Note region to change; ColdReopen requires its bytes unchanged.
pub(crate) fn note_disk(
    before: &[u8],
    after: &[u8],
    creation_catalogue: &[u8],
    expected_counter: u64,
    expected_note: &str,
) -> Result<Value> {
    let (app, context) = creation(creation_catalogue)?;
    compare_note(before, after, app, context, expected_counter, expected_note)
}
fn compare_note(
    before: &[u8],
    after: &[u8],
    app: ev_zion::AppId,
    context: GenerationManifest,
    expected_counter: u64,
    expected_note: &str,
) -> Result<Value> {
    if before.len() != storage::DISK_BYTES || after.len() != storage::DISK_BYTES {
        return Err("session note before/after extent differs".into());
    }
    if before[..FIRST] != after[..FIRST] || before[END..] != after[END..] {
        return Err("session changed bytes outside Note112..125".into());
    }
    let (old, prior) = inspect(before, app, context)?;
    let (actual, current) = inspect(after, app, context)?;
    if actual.counter() != expected_counter
        || actual.note() != expected_note
        || ![Some(old.counter()), old.counter().checked_add(1)].contains(&Some(expected_counter))
    {
        return Err("session durable Note differs from exact expected counter/content".into());
    }
    if actual.counter() == old.counter() && before[FIRST..END] != after[FIRST..END] {
        return Err("session readonly note load changed its Store bytes".into());
    }
    Ok(
        json!({"schema":1,"passed":true,"scope":"Independent read-only actual Store opens and complete byte comparison; saved GUI/ACK alone is not durable proof","before":prior,"after":current,"note":actual.note(),"outside_note_bytes_unchanged":true,"before_disk_sha256":format!("{:x}",Sha256::digest(before)),"after_disk_sha256":format!("{:x}",Sha256::digest(after))}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_store::{BootPolicy, OperationId, Request};
    fn view<'a>(note: &'a [u8], state: ev_graphics::session::SaveState) -> View<'a> {
        View {
            build: ev_graphics::native::Build::A,
            focus: ev_graphics::session::Focus::Note,
            note,
            state,
            file: None,
        }
    }
    fn ppm(reference: &Reference) -> Vec<u8> {
        // Deliberate host data-only raster fixture, never a guest capture.
        let mut out = b"P6\n800 600\n255\n".to_vec();
        for y in 0..600 {
            for x in 0..800 {
                out.extend_from_slice(&reference.pixel(x, y, 800, 600));
            }
        }
        out
    }
    #[test]
    fn fresh_app_gate_rejects_cached_frame_before_current_shell_and_requires_its_real_barrier() {
        let build = "a".repeat(64);
        let reference = Reference::new(
            Screen::AppRunning,
            Some(view(b"kept note", ev_graphics::session::SaveState::Saved)),
            None,
        )
        .unwrap();
        let app = Step {
            kind: StepKind::Frame,
            frame: 9,
            width: 1280,
            height: 800,
            app_process: 12,
            shell_process: 9,
            display_process: 3,
            grants: 0,
            producer: Producer::App,
            surface_sha256: reference.surface_hash(Producer::App, 9).unwrap(),
            held_ticks: 0,
        };
        let shell = Step {
            producer: Producer::Shell,
            frame: 8,
            surface_sha256: reference.surface_hash(Producer::Shell, 8).unwrap(),
            ..app.clone()
        };
        let barrier = format!(
            "\n\n\n\n\n\nEVROSION_M6_BARRIER protocol=1 build={build} count=1 call_epoch=501 call=1 endpoint=34 caller_process=9 caller_thread=9 callee_process=5 callee_thread=5 frame=8 sequence=0 flags=0 buttons=0 request=000000083252424b reply=0000000000000242 tick=10\n"
        );
        let ui = crate::session_io::ProbeUi::parse(barrier.as_bytes(), &build).unwrap();
        assert!(reference.app_composition_ready(&app, Some(&shell)).unwrap());
        assert!(
            !reference.fresh_app_ready(&app, 3, &shell, 4, &ui).unwrap(),
            "same hashes and a later Shell barrier cannot freshen an earlier App frame"
        );
        assert!(reference.fresh_app_ready(&app, 7, &shell, 4, &ui).unwrap());
        let no_barrier = crate::session_io::ProbeUi::parse(b"", &build).unwrap();
        assert!(
            !reference
                .fresh_app_ready(&app, 7, &shell, 4, &no_barrier)
                .unwrap()
        );
        let wrong_caller = crate::session_io::ProbeUi::parse(
            barrier
                .replace("caller_process=9", "caller_process=17")
                .as_bytes(),
            &build,
        )
        .unwrap();
        assert!(
            !reference
                .fresh_app_ready(&app, 7, &shell, 4, &wrong_caller)
                .unwrap()
        );
        let mut newer_shell = shell.clone();
        newer_shell.frame = 10;
        newer_shell.surface_sha256 = reference.surface_hash(Producer::Shell, 10).unwrap();
        assert!(
            !reference
                .fresh_app_ready(&app, 7, &newer_shell, 4, &ui)
                .unwrap()
        );
        let mut wrong_app = app.clone();
        wrong_app.app_process += 1;
        assert!(
            !reference
                .fresh_app_ready(&wrong_app, 7, &shell, 4, &ui)
                .unwrap()
        );
        let mut wrong_surface = app.clone();
        wrong_surface.surface_sha256 = "f".repeat(64);
        assert!(
            !reference
                .fresh_app_ready(&wrong_surface, 7, &shell, 4, &ui)
                .unwrap()
        );
        // Fresh chronology still grants no pixel equivalence or retry credit.
        let mut pixels = ppm(&reference);
        *pixels.last_mut().unwrap() ^= 1;
        assert!(reference.validate(&Ppm::parse(pixels).unwrap()).is_err());
    }
    #[test]
    fn actual_scanout_comparison_includes_case_note_state_cursor_and_full_geometry() {
        let reference = Reference::new(
            Screen::AppRunning,
            Some(view(b"aA_!?", ev_graphics::session::SaveState::Saved)),
            Some((310, 190)),
        )
        .unwrap();
        let raw = ppm(&reference);
        assert!(
            reference
                .validate(&Ppm::parse(raw.clone()).unwrap())
                .is_ok()
        );
        let mut bad = raw;
        *bad.last_mut().unwrap() ^= 1;
        assert!(reference.validate(&Ppm::parse(bad).unwrap()).is_err());
        for (note, state) in [
            (b"AA_!?".as_slice(), ev_graphics::session::SaveState::Saved),
            (b"aA_!?", ev_graphics::session::SaveState::Unsaved),
        ] {
            let changed = Reference::new(
                Screen::AppRunning,
                Some(view(note, state)),
                Some((310, 190)),
            )
            .unwrap();
            assert_ne!(
                reference.surface_hash(Producer::App, 1).unwrap(),
                changed.surface_hash(Producer::App, 1).unwrap()
            );
        }
        let without = Reference::new(
            Screen::AppRunning,
            Some(view(b"aA_!?", ev_graphics::session::SaveState::Saved)),
            None,
        )
        .unwrap();
        assert_eq!(
            reference.surface_hash(Producer::App, 1).unwrap(),
            without.surface_hash(Producer::App, 1).unwrap()
        );
        assert!(
            reference
                .validate(&Ppm::parse(ppm(&without)).unwrap())
                .is_err()
        );
        assert!(
            Reference::new(
                Screen::Home,
                Some(view(b"", ev_graphics::session::SaveState::Saved)),
                None
            )
            .is_err()
        );
        assert!(Reference::new(Screen::Home, None, Some((320, 0))).is_err());
        assert!(
            Reference::new(Screen::Home, None, None)
                .unwrap()
                .surface_hash(Producer::App, 1)
                .is_err()
        );
    }
    #[derive(Clone)]
    struct Memory {
        bytes: Vec<u8>,
        start: usize,
        fail_flush: bool,
    }
    impl SectorIo for Memory {
        type Error = ();
        fn sectors(&self) -> u64 {
            ev_store::REQUIRED_SECTORS
        }
        fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> core::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            let start = self.start * 512 + lba as usize * 512;
            out.copy_from_slice(&self.bytes[start..start + 512]);
            Ok(())
        }
        fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> core::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            let start = self.start * 512 + lba as usize * 512;
            self.bytes[start..start + 512].copy_from_slice(bytes);
            Ok(())
        }
        fn flush(&mut self, _: u64) -> core::result::Result<(), ()> {
            if self.fail_flush { Err(()) } else { Ok(()) }
        }
    }
    fn app() -> ev_zion::AppId {
        ev_zion::AppId::new([7; 16]).unwrap()
    }
    fn context() -> GenerationManifest {
        GenerationManifest {
            generation: GenerationId::new(1).unwrap(),
            cohort: [3; 32],
            supervisor_image: [4; 32],
            abi: FORMAT_ABI,
            health_contract: Sha256::digest(b"note-namespace-creation-only; no health claim")
                .into(),
            health_version: 1,
            required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
        }
    }
    fn formatted(body: &[u8], ctx: GenerationManifest) -> Memory {
        let mut bytes = vec![0; storage::DISK_BYTES];
        bytes[0] = 0x53;
        bytes[END + 7] = 0xa9;
        Store::format_new(
            Memory {
                bytes,
                start: 112,
                fail_flush: false,
            },
            ctx,
            body,
            BootPolicy::new(1).unwrap(),
            DEADLINE,
        )
        .map_err(|_| ())
        .unwrap()
        .into_device()
    }
    struct Initial {
        catalogue: Vec<u8>,
        packages: [Vec<u8>; 2],
        before: Vec<u8>,
        baseline: Vec<u8>,
    }
    fn initial() -> Initial {
        use ev_userspace_contract::root_v2::{self, catalogue as base, native::catalogue as cat};
        // Actual tiny retained ELF/container bytes; this is metadata + real
        // in-memory Store publication, never an executed desktop/seed proof.
        let elf = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
        let a = crate::native_package::session_hello(elf, [1; 32]).unwrap();
        let mut other = elf.to_vec();
        other.push(0x42);
        let b = crate::native_package::session_hello(&other, [2; 32]).unwrap();
        let images = core::array::from_fn(|i| base::Image {
            role: root_v2::graph::CHILDREN[i].image(),
            image: if i == 4 {
                a.executable
            } else {
                [i as u8 + 10; 32]
            },
            descriptor: if i == 4 {
                a.descriptor
            } else {
                [i as u8 + 20; 32]
            },
            abi: ev_userspace_contract::ABI,
            limits: base::CHILD_LIMITS,
            display_layout: i == 5,
            grants: base::CHILD_ROLE_COUNTS[i],
            roles: ev_root_supervisor::desktop_plan::roles_measurement(root_v2::graph::CHILDREN[i]),
        });
        let description = |graph| base::Description {
            root_image: [1; 32],
            kernel_input: [2; 32],
            graph,
            app_id: a.app,
            package: a.package,
            app_build: a.build,
            provenance: base::Provenance::Zion,
            restart_attempts: 3,
            restart_window: 60000,
            images,
        };
        let temporary = base::encode(description([0; 32])).unwrap();
        let graph = ev_root_supervisor::desktop_plan::graph_measurement(
            &base::Catalogue::decode(&temporary).unwrap(),
        );
        let base = base::encode(description(graph)).unwrap();
        let description = |layout_measurement| cat::Description {
            base: &base,
            app_b: cat::AppImage {
                image: b.executable,
                descriptor: b.descriptor,
                abi: ev_userspace_contract::ABI,
                limits: base::CHILD_LIMITS,
                roles: ev_root_supervisor::desktop_plan::roles_measurement(
                    root_v2::graph::Child::App,
                ),
            },
            bad_shell: cat::AppImage {
                image: [0x91; 32],
                descriptor: [0x92; 32],
                abi: ev_userspace_contract::ABI,
                limits: base::CHILD_LIMITS,
                roles: ev_root_supervisor::desktop_plan::roles_measurement(
                    root_v2::graph::Child::Shell,
                ),
            },
            boot_mode: cat::BootMode::Standalone,
            package_b: b.package,
            package_b_build: b.build,
            package_a_bytes: a.bytes.len() as u64,
            package_b_bytes: b.bytes.len() as u64,
            layout_measurement,
        };
        let temporary = cat::encode(description([1; 32])).unwrap();
        let layout = ev_root_supervisor::native_plan::session_layout_measurement(
            &Catalogue::decode(&temporary).unwrap(),
        );
        let catalogue = cat::encode(description(layout)).unwrap().to_vec();
        let (app, note_context) = creation(&catalogue).unwrap();
        let cat = Catalogue::decode(&catalogue).unwrap();
        let banks = banks(&cat, [&a.bytes, &b.bytes]).unwrap();
        let mut before = vec![0x9b; storage::DISK_BYTES];
        for start in [64, 80, 112] {
            before[start * 512..(start + 14) * 512].fill(0);
        }
        let mut registry = ev_app_registry::Registry::format_new(
            Memory {
                bytes: before.clone(),
                start: 64,
                fail_flush: false,
            },
            ev_app_registry::Policy {
                app,
                abi: ev_userspace_contract::ABI,
                platform: 1,
            },
            scalar_creation(&cat, 64),
            DEADLINE,
        )
        .map_err(|_| ())
        .unwrap();
        for change in [
            ev_app_registry::Change::Install {
                package: a.package,
                data_epoch: 1,
            },
            ev_app_registry::Change::Activate,
        ] {
            let intent = registry
                .prepare(
                    registry.expected().unwrap(),
                    change,
                    &banks,
                    &ev_root_supervisor::native_plan::Contracts,
                )
                .unwrap();
            registry
                .publish(
                    intent,
                    &banks,
                    &ev_root_supervisor::native_plan::Contracts,
                    DEADLINE,
                )
                .unwrap();
        }
        let mut device = registry.into_parts().0;
        device.start = 80;
        let mut device = Store::format_new(
            device,
            scalar_creation(&cat, 80),
            &ev_app_registry::app_data::AppDataEnvelope::initial(app, 1, 1001)
                .unwrap()
                .encode(),
            BootPolicy::new(1).unwrap(),
            DEADLINE,
        )
        .map_err(|_| ())
        .unwrap()
        .into_device();
        device.start = 112;
        let baseline = Store::format_new(
            device,
            note_context,
            &NoteDataEnvelope::initial(app, "").unwrap().encode(),
            BootPolicy::new(1).unwrap(),
            DEADLINE,
        )
        .map_err(|_| ())
        .unwrap()
        .into_device()
        .bytes;
        Initial {
            catalogue,
            packages: [a.bytes, b.bytes],
            before,
            baseline,
        }
    }
    #[test]
    fn explicit_gui_initialization_resolves_real_registry_scalar_and_note_without_masking_original_bytes()
     {
        let f = initial();
        let packages = [f.packages[0].as_slice(), f.packages[1].as_slice()];
        let result = initialization(&f.before, &f.baseline, &f.catalogue, packages).unwrap();
        assert_eq!(result["registry"]["revision"], 2);
        assert_eq!(result["scalar_data"]["value"], 1001);
        assert_eq!(result["note"]["counter"], 0);
        for sector in [0, 16, 32, 48, 63, 78, 79, 94, 95, 96, 110, 111, 126, 8191] {
            let mut bad = f.baseline.clone();
            bad[sector * 512 + 7] ^= 1;
            assert!(initialization(&f.before, &bad, &f.catalogue, packages).is_err());
        }
        for sector in [64, 80, 112] {
            let mut prior = f.before.clone();
            prior[sector * 512 + 9] = 1;
            assert!(initialization(&prior, &f.baseline, &f.catalogue, packages).is_err());
        }
        assert!(
            initialization(
                &f.before,
                &f.baseline,
                &f.catalogue,
                [packages[1], packages[0]]
            )
            .is_err()
        );
        let mut damaged = f.packages[0].clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(
            initialization(
                &f.before,
                &f.baseline,
                &f.catalogue,
                [&damaged, packages[1]]
            )
            .is_err()
        );
    }
    #[test]
    fn checksum_valid_wrong_creation_extra_registry_operation_and_nonempty_initial_note_refuse() {
        let f = initial();
        let package_bytes = [f.packages[0].as_slice(), f.packages[1].as_slice()];
        let cat = Catalogue::decode(&f.catalogue).unwrap();
        let (app, note_context) = creation(&f.catalogue).unwrap();
        let banks = banks(&cat, package_bytes).unwrap();
        let mut registry = ev_app_registry::Registry::open(
            Memory {
                bytes: f.baseline.clone(),
                start: 64,
                fail_flush: false,
            },
            ev_app_registry::Policy {
                app,
                abi: ev_userspace_contract::ABI,
                platform: 1,
            },
            &banks,
            &ev_root_supervisor::native_plan::Contracts,
            DEADLINE,
        )
        .map_err(|_| ())
        .unwrap();
        let intent = registry
            .prepare(
                registry.expected().unwrap(),
                ev_app_registry::Change::Stage {
                    package: banks.packages[1].id().bytes(),
                },
                &banks,
                &ev_root_supervisor::native_plan::Contracts,
            )
            .unwrap();
        registry
            .publish(
                intent,
                &banks,
                &ev_root_supervisor::native_plan::Contracts,
                DEADLINE,
            )
            .unwrap();
        assert!(
            initialization(
                &f.before,
                &registry.into_parts().0.bytes,
                &f.catalogue,
                package_bytes
            )
            .is_err()
        );
        for (start, ctx, body) in [
            (
                80,
                {
                    let mut m = scalar_creation(&cat, 80);
                    m.abi = [3; 32];
                    m
                },
                ev_app_registry::app_data::AppDataEnvelope::initial(app, 1, 1001)
                    .unwrap()
                    .encode(),
            ),
            (
                112,
                note_context,
                NoteDataEnvelope::initial(app, "unexpected initial data")
                    .unwrap()
                    .encode(),
            ),
        ] {
            let mut bytes = f.baseline.clone();
            bytes[start * 512..(start + 14) * 512].fill(0);
            let actual = Store::format_new(
                Memory {
                    bytes,
                    start,
                    fail_flush: false,
                },
                ctx,
                &body,
                BootPolicy::new(1).unwrap(),
                DEADLINE,
            )
            .map_err(|_| ())
            .unwrap()
            .into_device();
            assert!(initialization(&f.before, &actual.bytes, &f.catalogue, package_bytes).is_err());
        }
    }
    #[test]
    fn real_store_note_write_and_cold_read_prove_exact_operation_and_every_other_byte() {
        let initial = NoteDataEnvelope::initial(app(), "").unwrap();
        let before = formatted(&initial.encode(), context());
        let next = initial.checked_replace(app(), 0, "EvRo_42!?").unwrap();
        let mut store = Store::open(before.clone(), DEADLINE)
            .map_err(|_| ())
            .unwrap();
        store
            .execute(
                OperationId::new(1).unwrap(),
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &next.encode(),
                },
                DEADLINE,
            )
            .unwrap();
        let after = store.into_device();
        let result = compare_note(
            &before.bytes,
            &after.bytes,
            app(),
            context(),
            1,
            "EvRo_42!?",
        )
        .unwrap();
        assert_eq!(result["after"]["observer_mutations"], 0);
        assert!(compare_note(&after.bytes, &after.bytes, app(), context(), 1, "EvRo_42!?").is_ok());
        for index in [0, FIRST - 1, END, storage::DISK_BYTES - 1] {
            let mut bad = after.bytes.clone();
            bad[index] ^= 1;
            assert!(compare_note(&before.bytes, &bad, app(), context(), 1, "EvRo_42!?").is_err());
        }
        assert!(
            compare_note(
                &before.bytes,
                &after.bytes,
                app(),
                context(),
                0,
                "EvRo_42!?"
            )
            .is_err()
        );
        assert!(
            compare_note(
                &before.bytes,
                &after.bytes,
                app(),
                context(),
                1,
                "EVRO_42!?"
            )
            .is_err()
        );
        assert!(
            compare_note(
                &before.bytes[..FIRST],
                &after.bytes,
                app(),
                context(),
                1,
                "EvRo_42!?"
            )
            .is_err()
        );
        let mut same_counter = Store::open(after.clone(), DEADLINE)
            .map_err(|_| ())
            .unwrap();
        same_counter
            .execute(
                OperationId::new(2).unwrap(),
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &next.encode(),
                },
                DEADLINE,
            )
            .unwrap();
        assert!(
            compare_note(
                &after.bytes,
                &same_counter.into_device().bytes,
                app(),
                context(),
                1,
                "EvRo_42!?"
            )
            .is_err()
        );
    }
    #[test]
    fn wrong_format_identity_corruption_and_accepted_unknown_intent_never_authorize_observer_repair()
     {
        let note = NoteDataEnvelope::initial(app(), "").unwrap();
        let before = formatted(&note.encode(), context());
        let mut wrong = context();
        wrong.abi = [5; 32];
        let foreign = formatted(&note.encode(), wrong);
        assert!(inspect(&foreign.bytes, app(), context()).is_err());
        let other = formatted(
            &NoteDataEnvelope::initial(ev_zion::AppId::new([8; 16]).unwrap(), "")
                .unwrap()
                .encode(),
            context(),
        );
        assert!(inspect(&other.bytes, app(), context()).is_err());
        let scalar = formatted(
            &ev_app_registry::app_data::AppDataEnvelope::initial(app(), 1, 1001)
                .unwrap()
                .encode(),
            context(),
        );
        assert!(inspect(&scalar.bytes, app(), context()).is_err());
        let mut pending = before.clone();
        pending.fail_flush = true;
        let mut store = Store::open(pending, DEADLINE).map_err(|_| ()).unwrap();
        let next = note
            .checked_replace(app(), 0, "unknown publication")
            .unwrap();
        assert!(
            store
                .execute(
                    OperationId::new(1).unwrap(),
                    Request::WriteMutable {
                        object: ObjectId::user_data(),
                        bytes: &next.encode()
                    },
                    DEADLINE
                )
                .is_err()
        );
        let raw = store.into_device().bytes;
        let unchanged = raw.clone();
        assert!(inspect(&raw, app(), context()).is_err());
        assert_eq!(raw, unchanged);
        assert!(note_disk(&before.bytes, &before.bytes, b"EVGRAPH1", 0, "").is_err());
    }
}
