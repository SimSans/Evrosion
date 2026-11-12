//! Strict diagnostics and a host-only reference for the actual scanout proof.
//! Expected pixels verify an unmodified QMP capture; they never replace it.
use crate::{boot_protocol::canonical_number as number, build::Result, qmp::Ppm};
use ev_graphics::{Color, HEIGHT, Pixels, WIDTH};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Present {
    pub(crate) build: String,
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) app_process: u64,
    pub(crate) display_process: u64,
    pub(crate) surface_sha256: String,
}
fn hash(field: &str, name: &str) -> Result<String> {
    let value = field
        .strip_prefix(name)
        .and_then(|s| s.strip_prefix('='))
        .ok_or("missing display hash")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("display hash must be64 lowercase hexadecimal digits".into());
    }
    Ok(value.into())
}
pub(crate) fn present_line(line: &str, build: &str) -> Result<Present> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 512
        || f.len() != 9
        || f[0] != "EVROSION_M4_PRESENT"
        || f[1] != "protocol=1"
        || f[3] != "frame=1"
    {
        return Err("malformed display Present record".into());
    }
    let p = Present {
        build: hash(f[2], "build")?,
        width: usize::try_from(number(f[4], "width")?).map_err(|_| "display width overflow")?,
        height: usize::try_from(number(f[5], "height")?).map_err(|_| "display height overflow")?,
        app_process: number(f[6], "app_process")?,
        display_process: number(f[7], "display_process")?,
        surface_sha256: hash(f[8], "surface_sha256")?,
    };
    if p.build != build
        || !(800..=2048).contains(&p.width)
        || !(600..=2048).contains(&p.height)
        || p.app_process == 0
        || p.display_process == 0
        || p.app_process == p.display_process
    {
        return Err("wrong-build, geometry or process identity in Present record".into());
    }
    Ok(p)
}
fn unique<'a>(serial: &'a [u8], tag: &str) -> Result<Option<&'a str>> {
    if serial.len() > 1024 * 1024 {
        return Err("display serial exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "display serial is not UTF-8")?;
    let mut result = None;
    for line in text.split_inclusive('\n').filter(|l| l.starts_with(tag)) {
        if result.is_some() {
            return Err("duplicate display protocol record".into());
        }
        if !line.ends_with('\n') {
            return Ok(None);
        }
        result = Some(
            line.strip_suffix('\n')
                .unwrap()
                .strip_suffix('\r')
                .unwrap_or(line.strip_suffix('\n').unwrap()),
        );
    }
    Ok(result)
}
pub(crate) fn present(serial: &[u8], build: &str) -> Result<Option<Present>> {
    unique(serial, "EVROSION_M4_PRESENT ")?
        .map(|s| present_line(s, build))
        .transpose()
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Record {
    pub(crate) peak_frames: u64,
}
pub(crate) fn line(line: &str) -> Result<Record> {
    let f: Vec<_> = line.split(' ').collect();
    let expected = [
        "EVROSION_M4_DISPLAY",
        "status=PASS",
        "scope=surface",
        "worlds=3",
        "calls=2",
        "blocks=2",
        "wakes=2",
        "replies=1",
        "faults=2",
        "authority_denied=9",
        "mapped=6",
        "surface_pages=63",
        "display_tables=6",
    ];
    if line.len() > 512
        || f.len() != 18
        || f[..13] != expected
        || f[14..]
            != [
                "max_pending=1",
                "frames=true",
                "metadata=true",
                "guards=true",
            ]
    {
        return Err("malformed display lifecycle proof".into());
    }
    let peak_frames = number(f[13], "peak_frames")?;
    if !(1..=128).contains(&peak_frames) {
        return Err("display physical-frame peak exceeds declared128 bound".into());
    }
    Ok(Record { peak_frames })
}
pub(crate) fn record(serial: &[u8]) -> Result<Record> {
    line(unique(serial, "EVROSION_M4_DISPLAY ")?.ok_or("missing or truncated display proof")?)
}

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
        if x >= WIDTH || y >= HEIGHT || color.0 & 0xff00_0000 != 0 {
            return Err(ev_graphics::Error::Bounds);
        }
        self.0[y * WIDTH + x] = color;
        Ok(())
    }
}
pub(crate) struct Reference {
    pixels: Vec<Color>,
    pub(crate) surface_sha256: String,
}
impl Reference {
    pub(crate) fn hello() -> Result<Self> {
        let mut buffer = Buffer(vec![Color(0); WIDTH * HEIGHT]);
        ev_graphics::hello(
            &mut buffer,
            ev_graphics::HelloView {
                focus: ev_graphics::HelloControl::OpenFile,
                content: None,
                incarnation: 1,
            },
        )
        .map_err(|e| format!("host reference: {e:?}"))?;
        let mut hash = Sha256::new();
        hash.update(
            ev_graphics::SurfaceHeader { sequence: 1 }
                .encode()
                .map_err(|e| format!("host header: {e:?}"))?,
        );
        for color in &buffer.0 {
            hash.update(color.0.to_le_bytes());
        }
        let tail = ev_graphics::MAPPED_BYTES - ev_graphics::HEADER_BYTES - ev_graphics::PIXEL_BYTES;
        hash.update(vec![0; tail]);
        Ok(Self {
            pixels: buffer.0,
            surface_sha256: format!("{:x}", hash.finalize()),
        })
    }
    fn scanout_pixel(&self, x: usize, y: usize, width: usize, height: usize) -> [u8; 3] {
        let left = (width - WIDTH * 2) / 2;
        let top = (height - HEIGHT * 2) / 2;
        if x >= left && x < left + WIDTH * 2 && y >= top && y < top + HEIGHT * 2 {
            self.pixels[((y - top) / 2) * WIDTH + (x - left) / 2].components()
        } else if x + 2 >= left
            && x < left + WIDTH * 2 + 2
            && y + 2 >= top
            && y < top + HEIGHT * 2 + 2
        {
            ev_graphics::ACCENT.components()
        } else {
            ev_graphics::BACKGROUND.components()
        }
    }
    pub(crate) fn validate(&self, present: &Present, frame: &Ppm) -> Result<Value> {
        if present.surface_sha256 != self.surface_sha256 {
            return Err(
                "actual retained63-page surface differs from rendered reference/header/zero tail"
                    .into(),
            );
        }
        let (width, height) = frame.dimensions();
        if (width, height) != (present.width, present.height) {
            return Err("actual QMP scanout differs from trusted Present geometry".into());
        }
        let mut actual = Sha256::new();
        let mut expected = Sha256::new();
        for y in 0..height {
            for x in 0..width {
                let pixel = frame.pixel(x, y)?;
                let want = self.scanout_pixel(x, y, width, height);
                actual.update(pixel);
                expected.update(want);
                if pixel != want {
                    return Err(format!(
                        "actual QMP scanout pixel mismatch at({x},{y}): {pixel:?} != {want:?}"
                    ));
                }
            }
        }
        Ok(
            json!({"source":"unmodified QMP P6 scanout","width":width,"height":height,"checked_pixels":width*height,
            "actual_rgb_sha256":format!("{:x}",actual.finalize()),"expected_rgb_sha256":format!("{:x}",expected.finalize()),
            "surface_sha256":self.surface_sha256,"surface_bytes":ev_graphics::MAPPED_BYTES,"zero_tail_bytes":ev_graphics::MAPPED_BYTES-ev_graphics::HEADER_BYTES-ev_graphics::PIXEL_BYTES,
            "scale":2,"border_pixels":2,"whole_scanout_matches":true}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const BUILD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    fn present_text() -> String {
        format!(
            "EVROSION_M4_PRESENT protocol=1 build={BUILD} frame=1 width=800 height=600 app_process=1 display_process=2 surface_sha256={}",
            Reference::hello().unwrap().surface_sha256
        )
    }
    pub(crate) const RECORD: &str = "EVROSION_M4_DISPLAY status=PASS scope=surface worlds=3 calls=2 blocks=2 wakes=2 replies=1 faults=2 authority_denied=9 mapped=6 surface_pages=63 display_tables=6 peak_frames=110 max_pending=1 frames=true metadata=true guards=true";
    #[test]
    fn strict_records_reject_wrong_build_identity_order_counters_and_bounds() {
        assert_eq!(line(RECORD).unwrap().peak_frames, 110);
        for (old, new) in [
            ("peak_frames=110", "peak_frames=129"),
            ("mapped=6", "mapped=5"),
            ("faults=2", "faults=0"),
            ("calls=2", "calls=02"),
            ("guards=true", "guards=false"),
        ] {
            assert!(line(&RECORD.replace(old, new)).is_err());
        }
        let p = present_text();
        assert!(present_line(&p, BUILD).is_ok());
        for (old, new) in [
            ("protocol=1", "protocol=2"),
            ("app_process=1", "app_process=0"),
            ("display_process=2", "display_process=1"),
            ("width=800", "width=799"),
            ("frame=1", "frame=2"),
        ] {
            assert!(present_line(&p.replace(old, new), BUILD).is_err());
        }
        assert!(present_line(&p, &"a".repeat(64)).is_err());
        assert!(record(format!("{RECORD}\r\n{RECORD}\r\n").as_bytes()).is_err());
        assert!(record(RECORD.as_bytes()).is_err());
        assert_eq!(present(p.as_bytes(), BUILD).unwrap(), None);
    }
    #[test]
    fn actual_ppm_must_match_every_pixel_header_tail_and_geometry() {
        let reference = Reference::hello().unwrap();
        let present = present_line(&present_text(), BUILD).unwrap();
        let mut bytes = b"P6\n800 600\n255\n".to_vec();
        for y in 0..600 {
            for x in 0..800 {
                bytes.extend_from_slice(&reference.scanout_pixel(x, y, 800, 600));
            }
        }
        reference
            .validate(&present, &Ppm::parse(bytes.clone()).unwrap())
            .unwrap();
        for index in [bytes.len() - 1, bytes.len() / 2] {
            let mut wrong = bytes.clone();
            wrong[index] ^= 1;
            assert!(
                reference
                    .validate(&present, &Ppm::parse(wrong).unwrap())
                    .is_err()
            );
        }
        let mut wrong = present.clone();
        wrong.surface_sha256 = "0".repeat(64);
        assert!(
            reference
                .validate(&wrong, &Ppm::parse(bytes.clone()).unwrap())
                .is_err()
        );
        let mut wrong = present;
        wrong.width = 801;
        assert!(
            reference
                .validate(&wrong, &Ppm::parse(bytes).unwrap())
                .is_err()
        );
    }
}
