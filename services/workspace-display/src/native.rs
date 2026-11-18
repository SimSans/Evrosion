//! Actual fixed mapping/scalar/volatile boundary. No source bytes are touched
//! before captured serving origin resolves their registered producer.
use core::arch::asm;
use ev_graphics::{Color, Pixels};
use ev_userspace_contract::root_v5::{
    child,
    display_control::{self as control, Envelope, Slot},
    graph::Child,
    surface::Header,
};
use ev_userspace_runtime as rt;
use ev_workspace_display::{ControlAuthority, CreditStatus, Origin, State};
use ev_workspace_shell::composition::{ComposeError, FramePixels, Raster};
use ev_workspace_shell::cursor::{Cursor, Error as CursorError, Scanout};

fn require(value: bool, code: u64) {
    if !value {
        rt::exit(code);
    }
}
fn now() -> u64 {
    let r = rt::monotonic();
    require(
        r.status == 0 && r.capability == 0 && r.value != u64::MAX,
        1300,
    );
    r.value
}
fn exact_rights(handle: u64, rights: u16) {
    for bit in [1, 2, 4, 8, 16, 32, 64, 128, 256] {
        let r = rt::inspect(handle, bit);
        require(
            r.value == 0
                && r.capability == 0
                && r.status == if u64::from(rights) & bit != 0 { 0 } else { 1 },
            1301,
        );
    }
}
fn capture(receiver: u64, nonce: u64) -> Option<Origin> {
    let mut values = [0; 8];
    for (field, value) in values.iter_mut().enumerate() {
        let r = rt::call4(
            rt::syscall::SERVING_ORIGIN,
            receiver,
            nonce,
            field as u64,
            0,
        );
        if r.status != 0 || r.capability != 0 || r.serial != 0 {
            return None;
        }
        *value = r.value;
    }
    let origin = Origin {
        process: values[0],
        thread: values[1],
        incarnation: values[2],
        call_epoch: values[3],
        serial: values[4],
        endpoint: values[5],
        deadline: values[6],
        status: values[7],
    };
    if origin.validate(nonce).is_err() || now() >= origin.deadline {
        return None;
    }
    Some(origin)
}
struct Credit {
    receiver: u64,
    origin: Origin,
}
impl Credit {
    fn new(receiver: u64, nonce: u64) -> Option<Self> {
        capture(receiver, nonce).map(|origin| Self { receiver, origin })
    }
    fn valid(&self) -> bool {
        // Kernel validates the actual callee, held RECEIVE, full nonce and
        // immutable retained Pending on every field query. Only field7 changes
        // during this loan. Kernel also compares its actual current tick with
        // the original deadline on this query, so no second clock syscall is
        // needed per row. Full capture+clock before/after and ACK are unchanged.
        let r = rt::call4(
            rt::syscall::SERVING_ORIGIN,
            self.receiver,
            self.origin.serial,
            7,
            0,
        );
        self.origin.kernel_checkpoint(CreditStatus {
            status: r.status,
            value: r.value,
            capability: r.capability,
            serial: r.serial,
        })
    }
    fn complete(&self) -> bool {
        capture(self.receiver, self.origin.serial) == Some(self.origin)
    }
}
struct Source {
    address: usize,
    pages: usize,
}
impl Source {
    /// # Safety
    /// Actual selected V5 loader has retained this actor's fixed READ-only RAM
    /// mapping to the exact SourceRole/MemoryObject, with no unmap/reuse during
    /// calls. A real accepted caller/credit is additionally required for access.
    unsafe fn at(base: usize, slot: Slot) -> Self {
        Self {
            address: base + slot.first_page() as usize * 4096,
            pages: slot.pages() as usize,
        }
    }
    fn snapshot<const N: usize>(&self, offset: usize, credit: &Credit) -> Option<[u8; N]> {
        if !credit.valid()
            || offset
                .checked_add(N)
                .is_none_or(|end| end > self.pages * 4096)
        {
            return None;
        }
        let mut bytes = [0; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            // SAFETY: exact checked initialized READ mapping and current actual
            // blocked sole writer, with retained call/mapping ownership above.
            *byte = unsafe {
                (self.address as *const u8)
                    .add(offset + index)
                    .read_volatile()
            };
        }
        if !credit.valid() {
            return None;
        }
        Some(bytes)
    }
}
struct CurrentFrame<'a> {
    source: &'a Source,
    credit: &'a Credit,
    header: Header,
}
impl FramePixels for CurrentFrame<'_> {
    fn raster(&self) -> Raster {
        Raster {
            width: self.header.width,
            height: self.header.height,
            stride_pixels: self.header.stride_bytes / 4,
            extent_bytes: u64::from(self.header.payload_bytes),
        }
    }
    fn checkpoint(&mut self) -> Result<(), ComposeError> {
        if self.credit.valid() {
            Ok(())
        } else {
            Err(ComposeError::Model(ev_workspace_shell::Error::Unsettled))
        }
    }
    #[inline(always)]
    fn sample(&self, x: u32, y: u32) -> Result<Color, ComposeError> {
        if x >= self.header.width || y >= self.header.height {
            return Err(ComposeError::Extent);
        }
        let offset = self.header.pixel_offset()
            + y as usize * self.header.stride_bytes as usize
            + x as usize * 4;
        if offset
            .checked_add(4)
            .is_none_or(|end| end > self.source.pages * 4096)
        {
            return Err(ComposeError::Extent);
        }
        // SAFETY: Root-installed producer was resolved from actual Kernel
        // origin before Header access; row checkpoints retain the exact serving
        // credit. Sole writer is blocked/exits on uncertain result; Root never
        // maps/writes ordinary sources, other consumers have READ only, no DMA.
        // No shared Rust slice/reference is fabricated over producer memory.
        let value = unsafe {
            (self.source.address as *const u8)
                .add(offset)
                .cast::<u32>()
                .read_volatile()
        };
        Ok(Color(value & 0x00ff_ffff))
    }
}
struct Device {
    address: usize,
    width: usize,
    height: usize,
    stride: usize,
    bytes: usize,
    bgr: bool,
}
impl Device {
    fn open(cap: u64) -> Self {
        let read = |field| {
            let r = rt::call(rt::syscall::DISPLAY_INFO, cap, field, 0);
            require(r.status == 0 && r.capability == 0, 1302);
            usize::try_from(r.value).unwrap_or_else(|_| rt::exit(1303))
        };
        let value = Self {
            address: read(1),
            width: read(2),
            height: read(3),
            stride: read(4),
            bytes: read(5),
            bgr: read(6) == 2,
        };
        let format = read(6);
        require(
            value.address != 0
                && value.address.is_multiple_of(4)
                && (640..=2048).contains(&value.width)
                && (480..=2048).contains(&value.height)
                && value.stride >= value.width
                && value.bytes <= 4 * 1024 * 1024
                && matches!(format, 1 | 2)
                && value
                    .stride
                    .checked_mul(value.height)
                    .and_then(|count| count.checked_mul(4))
                    .is_some_and(|needed| needed <= value.bytes)
                && value
                    .address
                    .checked_add(value.bytes)
                    .is_some_and(|end| end < (1usize << 47)),
            1304,
        );
        value
    }
    fn max_scale(&self) -> u8 {
        (self.width / 640).min(self.height / 480).min(4) as u8
    }
    fn output(&mut self, scale: u8) -> Output<'_> {
        let width = 640 * usize::from(scale);
        let height = 480 * usize::from(scale);
        require(width <= self.width && height <= self.height, 1305);
        let left = (self.width - width) / 2;
        let top = (self.height - height) / 2;
        Output {
            device: self,
            width,
            height,
            left,
            top,
        }
    }
    fn initialize(&mut self) {
        for y in 0..self.height {
            for x in 0..self.width {
                self.pixel(x, y, Color::rgb(8, 12, 18));
            }
        }
        self.synchronize();
    }
    #[inline(always)]
    fn pixel(&mut self, x: usize, y: usize, color: Color) {
        require(x < self.width && y < self.height, 1306);
        let [r, g, b] = color.components();
        let bytes = if self.bgr { [b, g, r, 0] } else { [r, g, b, 0] };
        let offset = (y * self.stride + x) * 4;
        require(offset + 4 <= self.bytes, 1307);
        // SAFETY: DISPLAY_INFO came through actual admitted Display capability8,
        // exact retained guarded MMIO aperture/stride/extent above. This actor is
        // sole writable scanout owner; initialized RAM cannot become an aperture.
        unsafe {
            (self.address as *mut u8)
                .add(offset)
                .cast::<u32>()
                .write_volatile(u32::from_le_bytes(bytes))
        };
    }
    fn synchronize(&mut self) {
        // SAFETY: sole admitted WC scanout owner. Complete actual pixel stores
        // before a successful full-frame reply releases producer read credit.
        unsafe { asm!("sfence", options(nostack, preserves_flags)) };
    }
}
impl Scanout for Device {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    fn read(&self, x: usize, y: usize) -> Result<u32, CursorError> {
        if x >= self.width || y >= self.height {
            return Err(CursorError::Geometry);
        }
        let offset = (y * self.stride + x) * 4;
        if offset + 4 > self.bytes {
            return Err(CursorError::Geometry);
        }
        // SAFETY: same exact retained READWRITE Display aperture; only this
        // compositor owns scanout. No producer surface is sampled here.
        Ok(unsafe {
            (self.address as *const u8)
                .add(offset)
                .cast::<u32>()
                .read_volatile()
        })
    }
    fn write(&mut self, x: usize, y: usize, raw: u32) -> Result<(), CursorError> {
        if x >= self.width || y >= self.height {
            return Err(CursorError::Geometry);
        }
        let offset = (y * self.stride + x) * 4;
        if offset + 4 > self.bytes {
            return Err(CursorError::Geometry);
        }
        // SAFETY: checked actual scanout extent, sole admitted compositor.
        unsafe {
            (self.address as *mut u8)
                .add(offset)
                .cast::<u32>()
                .write_volatile(raw)
        };
        Ok(())
    }
    fn encode(&self, color: Color) -> u32 {
        let [r, g, b] = color.components();
        u32::from_le_bytes(if self.bgr { [b, g, r, 0] } else { [r, g, b, 0] })
    }
    fn synchronize(&mut self) {
        // SAFETY: order this device owner's WC stores and underlying cursor
        // reads. No memory access or stack pointer is supplied by a producer.
        unsafe { asm!("mfence", options(nostack, preserves_flags)) };
    }
}
fn show_cursor(state: &State, device: &mut Device, cursor: &mut Cursor) {
    if let Some((x, y)) = state.cursor() {
        let scale = state.scene().preferences.scale;
        let left = (device.width - 640 * usize::from(scale)) / 2;
        let top = (device.height - 480 * usize::from(scale)) / 2;
        cursor
            .show(device, left, top, scale, x, y)
            .unwrap_or_else(|_| rt::exit(1325));
    }
}
struct Output<'a> {
    device: &'a mut Device,
    width: usize,
    height: usize,
    left: usize,
    top: usize,
}
impl Pixels for Output<'_> {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    #[inline(always)]
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), ev_graphics::Error> {
        if x >= self.width || y >= self.height {
            return Err(ev_graphics::Error::Bounds);
        }
        self.device.pixel(self.left + x, self.top + y, color);
        Ok(())
    }
}
fn reply(receiver: u64, nonce: u64, value: u64) {
    let r = rt::call4(rt::syscall::REPLY_RPC, receiver, value, 0, nonce);
    require(
        r.status == 0 && r.value == 0 && r.capability == 0 && r.serial == 0,
        1308,
    );
}
fn ready(events: u64, stop: u64) {
    let deadline = rt::execution::deadline(stop, now(), 512).unwrap_or_else(|_| rt::exit(1320));
    loop {
        require(now() < deadline, 1321);
        let sent = rt::send(events, ev_workspace_display::READY);
        require(sent.value == 0 && sent.capability == 0, 1316);
        match sent.status {
            0 => return,
            2 => {
                let yielded = rt::yield_now();
                require(
                    yielded.status == 0 && yielded.value == 0 && yielded.capability == 0,
                    1322,
                );
            }
            _ => rt::exit(1323),
        }
    }
}

pub fn run(record: u64, length: u64, stop: u64) -> ! {
    require(
        length == child::SIZE as u64
            && record.is_multiple_of(4096)
            && (509 * 4096..(1 << 47) - 4096).contains(&record),
        1309,
    );
    let base = record
        .checked_sub(509 * 4096)
        .unwrap_or_else(|| rt::exit(1310));
    require(base == 0x8000000000, 1311);
    // SAFETY: actual fixed readonly528-byte startup extent retained by selected
    // M8 loader. Syntax alone is not used as mapping/source authority.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    let profile = child::Profile::parse(Child::Display, bytes).unwrap_or_else(|_| rt::exit(1312));
    require(rt::execution::validate(stop, now(), true).is_ok(), 1324);
    for grant in profile.grants() {
        exact_rights(grant.handle, grant.rights);
    }
    let present = profile.handle(7).unwrap();
    let control = profile.handle(10).unwrap();
    let events = profile.handle(9).unwrap();
    let authority =
        ControlAuthority::from_validated_bootstrap(&profile).unwrap_or_else(|_| rt::exit(1313));
    let info = rt::call4(rt::syscall::SERVING_ORIGIN_INFO, 0, 0, 0, 0);
    require(
        info.status == 0
            && info.value == rt::syscall::SERVING_ORIGIN_V1
            && info.capability == 0
            && info.serial == 0,
        1314,
    );
    // SAFETY: each mapping is independently admitted/retained READ-only from its
    // exact V5 role1..6. No producer bytes are accessed until a live call credit.
    let sources = core::array::from_fn::<_, 6, _>(|index| unsafe {
        Source::at(base as usize, control::SLOTS[index])
    });
    let mut device = Device::open(profile.handle(8).unwrap());
    let mut cursor = Cursor::new();
    let mut state = State::new(device.max_scale()).unwrap_or_else(|_| rt::exit(1315));
    device.initialize();
    ready(events, stop);
    loop {
        if stop != 0 && now() >= stop {
            rt::exit(0);
        }
        let mut handled = false;
        for receiver in [control, present] {
            let incoming = rt::call4(rt::syscall::RECEIVE_RPC, receiver, 0, 0, 0);
            if incoming.status == 2 {
                require(
                    incoming.value == 0 && incoming.capability == 0 && incoming.serial == 0,
                    1317,
                );
                continue;
            }
            require(
                incoming.status == 0 && incoming.capability == 0 && incoming.serial != 0,
                1318,
            );
            handled = true;
            let Some(credit) = Credit::new(receiver, incoming.serial) else {
                reply(receiver, incoming.serial, control::DENIED);
                continue;
            };
            let result = if receiver == control {
                control_call(
                    &mut state,
                    &authority,
                    &sources[Slot::ProtectedRoot.index()],
                    &credit,
                    incoming.value,
                    &mut device,
                    &mut cursor,
                )
            } else {
                present_call(
                    &mut state,
                    &sources,
                    &credit,
                    incoming.value,
                    &mut device,
                    &mut cursor,
                )
            };
            reply(receiver, incoming.serial, result);
        }
        if !handled {
            let r = rt::yield_now();
            require(r.status == 0 && r.value == 0 && r.capability == 0, 1319);
        }
    }
}
fn control_call(
    state: &mut State,
    authority: &ControlAuthority,
    root: &Source,
    credit: &Credit,
    request: u64,
    device: &mut Device,
    cursor: &mut Cursor,
) -> u64 {
    let Some(bytes) = root.snapshot::<256>(control::OFFSET, credit) else {
        return control::DENIED;
    };
    let Ok(envelope) = Envelope::parse(&bytes) else {
        return control::DENIED;
    };
    if envelope.request != request {
        return control::DENIED;
    }
    let Ok(origin) = authority.capture(credit.receiver, credit.origin.serial, credit.origin) else {
        return control::DENIED;
    };
    let Ok(effect) = state.control(origin, envelope) else {
        return control::DENIED;
    };
    if effect.redraw || effect.cursor {
        cursor.hide(device).unwrap_or_else(|_| rt::exit(1326));
    }
    if effect.redraw {
        let scale = state.scene().preferences.scale;
        if state.redraw(&mut device.output(scale)).is_err() {
            return control::DENIED;
        }
        device.synchronize();
    }
    if effect.redraw || effect.cursor {
        show_cursor(state, device, cursor);
    }
    if !credit.complete() {
        return control::DENIED;
    }
    effect.reply
}
fn present_call(
    state: &mut State,
    sources: &[Source; 6],
    credit: &Credit,
    requested: u64,
    device: &mut Device,
    cursor: &mut Cursor,
) -> u64 {
    let Ok(slot) = state.resolve(credit.origin, credit.origin.serial) else {
        return control::DENIED;
    };
    let Some(bytes) = sources[slot.index()].snapshot::<256>(0, credit) else {
        return control::DENIED;
    };
    let Ok(header) = Header::parse(&bytes) else {
        return control::DENIED;
    };
    let Ok(plan) = state.prepare(credit.origin, credit.origin.serial, requested, slot, header)
    else {
        return control::DENIED;
    };
    let mut source = CurrentFrame {
        source: &sources[slot.index()],
        credit,
        header,
    };
    // Refused origins/headers reach no cursor or protected-plane writes. This
    // separately Root-controlled overlay uses only the compositor's scanout.
    cursor.hide(device).unwrap_or_else(|_| rt::exit(1327));
    if state
        .paint(
            plan,
            &mut source,
            &mut device.output(state.scene().preferences.scale),
        )
        .is_err()
    {
        show_cursor(state, device, cursor);
        return control::DENIED;
    }
    device.synchronize();
    show_cursor(state, device, cursor);
    if sources[slot.index()].snapshot::<256>(0, credit) != Some(bytes) || !credit.complete() {
        return control::DENIED;
    }
    state
        .commit_present(plan, credit.origin)
        .unwrap_or(control::DENIED)
}
