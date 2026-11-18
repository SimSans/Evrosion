//! Replaceable ordinary Shell panel. Buttons request windows; they never
//! approve owner prompts, confer focus or authorize another actor themselves.
#![no_std]
#![forbid(unsafe_code)]
use ev_graphics::{Canvas, Error as GraphicsError, INK, MUTED, PANEL, Pixels};
use ev_workspace_client::ui::Event;
pub struct Profile {
    pub process: u64,
    pub incarnation: u64,
    pub handles: [u64; 4],
}
pub fn profile(bytes: &[u8]) -> Option<Profile> {
    let b = ev_userspace_contract::Bootstrap::parse(bytes).ok()?;
    let limits: [u64; 4] = core::array::from_fn(|i| {
        u64::from_le_bytes(bytes[40 + i * 8..48 + i * 8].try_into().unwrap())
    });
    if limits != ev_userspace_contract::root_v5::resources::JOB_TEMPLATE_LIMITS[2]
        || b.grants().count() != 4
    {
        return None;
    }
    let specs = [(1, 7), (2, 8), (2, 272), (2, 8)];
    let mut handles = [0; 4];
    for (i, g) in b.grants().enumerate() {
        if g.selector != i as u64 + 1
            || (g.kind, g.rights) != specs[i]
            || handles[..i].contains(&g.handle)
        {
            return None;
        }
        handles[i] = g.handle;
    }
    Some(Profile {
        process: b.process(),
        incarnation: b.incarnation(),
        handles,
    })
}
pub fn request(instance: u16) -> Option<Event> {
    if (1..=4).contains(&instance) {
        Some(Event::Window(instance as u8))
    } else {
        None
    }
}
pub fn hit_test(width: usize, height: usize, x: usize, y: usize) -> Option<u16> {
    if width == 0 || width > 640 || height == 0 || height > 200 || x >= width || y >= height {
        return None;
    }
    let cell = width / 4;
    if cell == 0 || x / cell >= 4 {
        None
    } else {
        Some((x / cell + 1) as u16)
    }
}
pub fn render<P: Pixels>(p: &mut P) -> Result<(), GraphicsError> {
    let (w, h) = p.dimensions();
    if w == 0 || w > 640 || h == 0 || h > 200 {
        return Err(GraphicsError::Geometry);
    }
    Canvas::new(p).fill(PANEL)?;
    let cell = w / 4;
    for (i, name) in [b"Files".as_slice(), b"Editor 1", b"Editor 2", b"Inspector"]
        .into_iter()
        .enumerate()
    {
        let x = i * cell;
        if cell > 1 && h >= 7 {
            let y = (h - 7) / 2;
            let n = name.len().min(cell.saturating_sub(8) / 6);
            if x + 4 < w {
                Canvas::new(p).text_exact(x + 4, y, &name[..n], INK)?;
            }
            if x + cell > 0 && x + cell < w {
                Canvas::new(p).rect(x + cell - 1, 0, 1, h, MUTED)?;
            }
        }
    }
    Ok(())
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    struct PixelsMemory {
        w: usize,
        h: usize,
        count: usize,
    }
    impl Pixels for PixelsMemory {
        fn dimensions(&self) -> (usize, usize) {
            (self.w, self.h)
        }
        fn write(
            &mut self,
            x: usize,
            y: usize,
            _: ev_graphics::Color,
        ) -> Result<(), GraphicsError> {
            assert!(x < self.w && y < self.h);
            self.count += 1;
            Ok(())
        }
    }
    #[test]
    fn bounded_panel_pixels_and_requests_do_not_claim_window_state_or_owner_approval() {
        for (w, h) in [(1, 1), (80, 18), (640, 18), (640, 80)] {
            let mut p = PixelsMemory { w, h, count: 0 };
            render(&mut p).unwrap();
            assert!(p.count >= w * h);
            assert_eq!(hit_test(w, h, w, 0), None);
        }
        for instance in 1..=4 {
            assert_eq!(request(instance), Some(Event::Window(instance as u8)));
        }
        assert!(request(0).is_none());
        assert!(request(5).is_none());
        assert_eq!(hit_test(640, 18, 639, 17), Some(4));
    }
    #[test]
    fn shell_profile_is_four_exact_roles_and_never_reinterprets_an_app_profile() {
        use ev_userspace_contract::{Context, Grant, encode};
        let c = Context {
            epoch: 805,
            incarnation: 1,
            process: 7,
            limits: ev_userspace_contract::root_v5::resources::JOB_TEMPLATE_LIMITS[2],
            manifest: [1; 32],
            authority: [2; 32],
        };
        let g = [
            Grant {
                selector: 1,
                handle: 11,
                kind: 1,
                rights: 7,
            },
            Grant {
                selector: 2,
                handle: 12,
                kind: 2,
                rights: 8,
            },
            Grant {
                selector: 3,
                handle: 13,
                kind: 2,
                rights: 272,
            },
            Grant {
                selector: 4,
                handle: 14,
                kind: 2,
                rights: 8,
            },
        ];
        assert!(profile(&encode(c, &g).unwrap()).is_some());
        let mut bad = g;
        bad[2].rights = 8;
        assert!(profile(&encode(c, &bad).unwrap()).is_none());
    }
}
