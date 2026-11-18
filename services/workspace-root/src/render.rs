//! Protected Root pixels. Names are escaped byte-for-byte where the bounded
//! reference font lacks a glyph, so distinct UTF8 names are never conflated.
use ev_graphics::{ACCENT, BACKGROUND, Canvas, Color, DANGER, Error, INK, MUTED, Pixels};
use ev_userspace_contract::workspace::Entry;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Desktop,
    Picker,
    Consent,
    Revoke,
    System,
    Refused,
    Shutdown,
    ShutdownPending,
    Development,
    DevelopmentPending,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub process: u64,
    pub thread: u64,
    pub observed: u64,
    pub count: u64,
    pub code: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub editor: u8,
    pub process: u64,
    pub thread: u64,
    pub nonce: u64,
}
#[derive(Clone, Copy)]
pub struct View<'a> {
    pub mode: Mode,
    pub title: &'a [u8],
    pub status: &'a [u8],
    pub entry: Option<Entry>,
    pub writable: bool,
    pub layer: u8,
    pub refusal: Option<Refusal>,
    pub recipient: Option<Recipient>,
    /// All-zero means no recorded scope; valid Dataset/legacy IDs are nonzero.
    pub dataset: [u8; 16],
    pub development: Option<DevelopmentView>,
}
#[derive(Clone, Copy)]
pub struct DevelopmentView {
    pub source: crate::development::Source,
    pub previous: crate::Identity,
    pub nonce: u64,
    pub intent: crate::development::Intent,
    pub pending: bool,
    pub status: &'static [u8],
}
fn bytes_hex<const N: usize>(bytes: &[u8; N], out: &mut [u8]) {
    let digits = b"0123456789abcdef";
    for (i, b) in bytes.iter().copied().enumerate() {
        out[i * 2] = digits[usize::from(b >> 4)];
        out[i * 2 + 1] = digits[usize::from(b & 15)];
    }
}
fn text<P: Pixels>(
    pixels: &mut P,
    x: usize,
    y: usize,
    s: &[u8],
    color: Color,
) -> Result<(), Error> {
    if x >= 640 || y + 7 > 80 {
        return Err(Error::Bounds);
    }
    let n = s.len().min((640 - x) / 6);
    Canvas::new(pixels).text_exact(x, y, &s[..n], color)
}
fn hex(out: &mut [u8], value: u64) {
    let digits = b"0123456789abcdef";
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = digits[((value >> ((15 - i) * 4)) & 15) as usize];
    }
}
pub fn dataset_text(dataset: [u8; 16]) -> [u8; 34] {
    let mut text = *b"D=00000000000000000000000000000000";
    let digits = b"0123456789abcdef";
    for (i, byte) in dataset.into_iter().enumerate() {
        text[2 + i * 2] = digits[usize::from(byte >> 4)];
        text[3 + i * 2] = digits[usize::from(byte & 15)];
    }
    text
}
pub fn render<P: Pixels>(pixels: &mut P, view: View<'_>) -> Result<(), Error> {
    if pixels.dimensions() != (640, 80) {
        return Err(Error::Geometry);
    }
    Canvas::new(pixels).fill(BACKGROUND)?;
    for (x, label) in [
        (2, b"L1".as_slice()),
        (32, b"L2"),
        (62, b"L3"),
        (92, b"Controls"),
        (182, b"Open"),
        (252, b"Inspector"),
        (322, b"Shutdown"),
        (452, b"Restart"),
        (582, b"Revoke"),
    ] {
        text(pixels, x, 1, label, INK)?;
    }
    if (1..=3).contains(&view.layer) {
        text(
            pixels,
            usize::from(view.layer - 1) * 30 + 18,
            1,
            b"*",
            ACCENT,
        )?;
    }
    text(
        pixels,
        2,
        11,
        &view.title[..view.title.len().min(if view.dataset != [0; 16] {
            50
        } else if view.recipient.is_some() {
            86
        } else {
            106
        })],
        if view.mode == Mode::Refused {
            DANGER
        } else {
            ACCENT
        },
    )?;
    if view.dataset != [0; 16] {
        text(pixels, 306, 11, &dataset_text(view.dataset), ACCENT)?;
    }
    if let Some(recipient) = view.recipient {
        let mut nonce = if view.mode == Mode::System {
            *b" op=0000000000000000"
        } else {
            *b"  n=0000000000000000"
        };
        hex(&mut nonce[4..20], recipient.nonce);
        text(pixels, 520, 11, &nonce, ACCENT)?;
        let mut who = *b"E1 P0000000000000000 T0000000000000000";
        if !(1..=2).contains(&recipient.editor) {
            return Err(Error::Geometry);
        }
        who[1] = b'0' + recipient.editor;
        hex(&mut who[4..20], recipient.process);
        hex(&mut who[22..38], recipient.thread);
        text(
            pixels,
            400,
            if view.entry.is_some() { 21 } else { 31 },
            &who,
            MUTED,
        )?;
    }
    if let Some(entry) = view.entry {
        let mut meta = *b"Object 0000 generation 0000000000000000 revision 0000000000000000";
        let digits = b"0123456789abcdef";
        for i in 0..4 {
            meta[7 + i] = digits[((entry.object.slot >> ((3 - i) * 4)) & 15) as usize];
        }
        hex(&mut meta[23..39], entry.object.generation);
        hex(&mut meta[49..65], entry.revision);
        text(pixels, 2, 21, &meta, MUTED)?;
        let mut escaped = [0u8; 384];
        let mut at = 0;
        for byte in entry.name.as_bytes().iter().copied() {
            if byte.is_ascii_graphic() && byte != b'\\' || byte == b' ' {
                escaped[at] = byte;
                at += 1;
            } else {
                escaped[at..at + 2].copy_from_slice(b"\\x");
                escaped[at + 2] = digits[usize::from(byte >> 4)];
                escaped[at + 3] = digits[usize::from(byte & 15)];
                at += 4;
            }
        }
        for (row, line) in escaped[..at].chunks(106).enumerate() {
            text(pixels, 2, 31 + row * 10, line, INK)?;
        }
    } else {
        text(pixels, 2, 23, view.status, INK)?;
        if let Some(refusal) = view.refusal {
            let mut line = *b"Last refusal PID 0000000000000000 thread 0000000000000000 code 00";
            hex(&mut line[17..33], refusal.process);
            hex(&mut line[41..57], refusal.thread);
            let digits = b"0123456789abcdef";
            line[63] = digits[usize::from(refusal.code >> 4)];
            line[64] = digits[usize::from(refusal.code & 15)];
            text(pixels, 2, 41, &line, DANGER)?;
            let mut line = *b"Refusal count 0000000000000000 Root observed tick 0000000000000000";
            hex(&mut line[14..30], refusal.count);
            hex(&mut line[50..66], refusal.observed);
            text(pixels, 2, 51, &line, MUTED)?;
        }
    }
    if let Some(development) = view.development {
        if matches!(view.mode, Mode::Development | Mode::DevelopmentPending) {
            Canvas::new(pixels).rect(0, 21, 640, 59, BACKGROUND)?;
            let mut app = *b"App 00000000000000000000000000000000";
            bytes_hex(&development.source.app, &mut app[4..36]);
            text(pixels, 2, 21, &app, INK)?;
            let mut old = *b"P0000000000000000 T0000000000000000 I0000000000000000";
            hex(&mut old[1..17], development.previous.process);
            hex(&mut old[19..35], development.previous.thread);
            hex(&mut old[37..53], development.previous.registered);
            text(pixels, 260, 21, &old, MUTED)?;
            for (y, label, value) in [
                (31, b"Zion ".as_slice(), development.source.package),
                (41, b"ELF  ".as_slice(), development.source.image),
                (51, b"Build".as_slice(), development.source.build),
            ] {
                let mut line = [b' '; 71];
                line[..label.len()].copy_from_slice(label);
                bytes_hex(&value, &mut line[7..71]);
                text(pixels, 2, y, &line, MUTED)?;
            }
            let mut nonce = *b" n=0000000000000000";
            hex(&mut nonce[3..19], development.nonce);
            text(pixels, 520, 11, &nonce, ACCENT)?;
            text(
                pixels,
                2,
                61,
                b"Unsigned local development; private app data; existing files retained",
                MUTED,
            )?;
            if !development.pending {
                text(pixels, 302, 71, b"Confirm [Enter]", ACCENT)?;
                text(pixels, 502, 71, b"Cancel [Esc]", ACCENT)?;
            } else {
                text(pixels, 2, 71, development.status, MUTED)?;
            }
        } else if view.mode == Mode::Desktop {
            text(pixels, 2, 71, b"Install local .zion", ACCENT)?;
            text(pixels, 152, 71, b"Run installed app", ACCENT)?;
        }
    } else if view.mode == Mode::Shutdown {
        text(pixels, 302, 71, b"Confirm [Enter]", ACCENT)?;
        text(pixels, 502, 71, b"Cancel [Esc]", ACCENT)?;
    } else if view.mode == Mode::ShutdownPending {
        text(
            pixels,
            2,
            71,
            b"Confirmed shutdown: unfinished work remains retained until checked completion",
            MUTED,
        )?;
    } else if view.mode == Mode::Revoke {
        text(
            pixels,
            2,
            71,
            if view.writable {
                b"Revoke READ/WRITE"
            } else {
                b"Revoke READ ONLY"
            },
            ACCENT,
        )?;
        text(pixels, 302, 71, b"Confirm revoke [Enter]", ACCENT)?;
        text(pixels, 502, 71, b"Cancel [Esc]", ACCENT)?;
    } else if matches!(view.mode, Mode::Picker | Mode::Consent) {
        for (x, label) in [
            (2, b"Prev".as_slice()),
            (52, b"Next"),
            (102, b"Up"),
            (
                152,
                if view.writable {
                    b"READ/WRITE".as_slice()
                } else {
                    b"READ ONLY"
                },
            ),
            (252, b"Src[V]"),
            (302, b"Confirm [Enter]"),
            (502, b"Cancel [Esc]"),
        ] {
            text(pixels, x, 71, label, ACCENT)?;
        }
    } else if view.mode == Mode::Refused {
        text(pixels, 252, 71, b"Src[V]", ACCENT)?;
        text(pixels, 502, 71, b"Cancel [Esc]", ACCENT)?;
    } else if view.mode == Mode::System {
        text(
            pixels,
            2,
            71,
            &view.status[..view.status.len().min(82)],
            MUTED,
        )?;
        text(pixels, 502, 71, b"Cancel binding [Esc]", ACCENT)?;
    }
    Ok(())
}

/// Full actual recipients and scope displayed by the independently owned Root
/// plane before its barrier and single-use owner confirmation.
#[derive(Clone, Copy)]
pub struct AssistiveView {
    pub inspector: crate::Identity,
    pub target: crate::Identity,
    pub slot: u8,
    pub window_generation: u64,
    pub rights: u8,
    pub nonce: u64,
    pub layer: u8,
}
pub fn assistive<P: Pixels>(pixels: &mut P, view: AssistiveView) -> Result<(), Error> {
    render(
        pixels,
        View {
            mode: Mode::Desktop,
            title: b"Approve exact Inspector semantic access",
            status: b"Scope persists only for the actual selected owner",
            entry: None,
            writable: false,
            layer: view.layer,
            refusal: None,
            recipient: None,
            dataset: [0; 16],
            development: None,
        },
    )?;
    Canvas::new(pixels).rect(0, 21, 640, 59, BACKGROUND)?;
    let mut client = *b"Inspector P0000000000000000 T0000000000000000 I0000000000000000";
    hex(&mut client[11..27], view.inspector.process);
    hex(&mut client[29..45], view.inspector.thread);
    hex(&mut client[47..63], view.inspector.registered);
    text(pixels, 2, 21, &client, MUTED)?;
    let mut target = *b"Target 0 P0000000000000000 T0000000000000000 I0000000000000000";
    target[7] = b'0' + view.slot;
    hex(&mut target[10..26], view.target.process);
    hex(&mut target[28..44], view.target.thread);
    hex(&mut target[46..62], view.target.registered);
    text(pixels, 2, 31, &target, INK)?;
    text(
        pixels,
        420,
        31,
        match view.slot {
            1 => b"Files",
            2 => b"Editor1",
            3 => b"Editor2",
            _ => b"Root protected",
        },
        ACCENT,
    )?;
    let mut scope = *b"Window 0000000000000000 nonce 0000000000000000 READ1 ACTION0 TEXT0 CONFIRM0";
    hex(&mut scope[7..23], view.window_generation);
    hex(&mut scope[30..46], view.nonce);
    scope[59] = b'0' + u8::from(view.rights & 2 != 0);
    scope[65] = b'0' + u8::from(view.rights & 4 != 0);
    scope[74] = b'0' + u8::from(view.rights & 8 != 0);
    text(pixels, 2, 41, &scope, ACCENT)?;
    text(
        pixels,
        2,
        51,
        if view.slot == 4 {
            b"Root READ includes current/future protected filenames and dialog metadata"
        } else {
            b"App READ covers its UI; TEXT includes current/future documents until revoked"
        },
        INK,
    )?;
    text(
        pixels,
        2,
        61,
        b"READ metadata; ACTION invokes controls; TEXT reads document bytes; CONFIRM is separate",
        MUTED,
    )?;
    for (x, name) in [
        (2, b"Prev".as_slice()),
        (52, b"Next"),
        (92, b"Action"),
        (182, b"Text"),
        (272, b"Protected confirm"),
        (402, b"Approve"),
        (502, b"Cancel"),
    ] {
        text(pixels, x, 71, name, ACCENT)?;
    }
    Ok(())
}
