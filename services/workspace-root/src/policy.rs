//! Four independent windows over the shared workspace-shell model. Layer
//! selection changes responsibility views only; it never approves an operation.
use crate::{Actor, Identity};
use ev_userspace_contract::root_v5::display_control::{Bounds, Slot};
use ev_workspace_shell::{
    Desktop, Error, Layer, Owner, Rect, Surface, TrustedAdapter, WindowId, WindowKind,
};

pub const CONTENT: Rect = Rect {
    x: 0,
    y: 91,
    width: 640,
    height: 371,
};

/// Route ordinary Escape only to the focused Editor's dedicated cancellation
/// request while its reported state is Saving. The App still validates its
/// actual phase, accepted Cancel presentation and original transfer cut. A
/// stale Root state must never turn this request into a generic Close action.
pub fn save_cancel_command(
    focused: Option<usize>,
    states: &[Option<ev_workspace_client::ui::State>; 4],
) -> Option<ev_workspace_client::ui::Command> {
    let index @ (1 | 2) = focused? else {
        return None;
    };
    (states[index] == Some(ev_workspace_client::ui::State::Saving)).then_some(
        ev_workspace_client::ui::Command::Activate(
            ev_workspace_client::ui::EDITOR_CANCEL_SAVE_ACTION,
        ),
    )
}

pub const fn initial_bounds(index: usize) -> Bounds {
    Bounds {
        x: if index.is_multiple_of(2) { 0 } else { 320 },
        y: if index < 2 { 91 } else { 282 },
        width: 320,
        height: 180,
    }
}
pub fn owner(identity: Identity) -> Owner {
    Owner {
        process: identity.process,
        incarnation: identity.registered,
    }
}
pub struct Policy {
    pub desktop: Desktop,
    /// Held only by the native Root controller, never an ordinary event handler.
    pub trusted: TrustedAdapter,
    pub shell: Owner,
    pub ids: [Option<WindowId>; 4],
    pub scene: u64,
}
impl Policy {
    #[inline(always)]
    pub fn new(shell: Identity, root: Identity) -> Result<Self, Error> {
        let shell = owner(shell);
        let (desktop, trusted) = Desktop::new(shell, owner(root), CONTENT)?;
        Ok(Self {
            desktop,
            trusted,
            shell,
            ids: [None; 4],
            scene: 0,
        })
    }
    pub fn install(&mut self, index: usize, actor: Actor) -> Result<(), Error> {
        if index >= 4 {
            return Err(Error::Missing);
        }
        let slot = [
            Slot::Files,
            Slot::EditorOne,
            Slot::EditorTwo,
            Slot::Inspector,
        ][index];
        let bounds = initial_bounds(index);
        let id = self.desktop.install(
            [
                WindowKind::Files,
                WindowKind::EditorOne,
                WindowKind::EditorTwo,
                WindowKind::Inspector,
            ][index],
            owner(actor.identity),
            Surface {
                object: slot.source().selector(),
                generation: actor.identity.process,
            },
            to_rect(bounds),
        )?;
        self.ids[index] = Some(id);
        Ok(())
    }
    pub fn retire(&mut self, index: usize, identity: Identity) -> Result<(), Error> {
        let id = self
            .ids
            .get(index)
            .copied()
            .flatten()
            .ok_or(Error::Missing)?;
        self.desktop.retire(id, owner(identity))?;
        self.ids[index] = None;
        Ok(())
    }
    pub fn focus(&mut self, index: usize) -> Result<(), Error> {
        self.desktop.activate(
            self.shell,
            self.ids
                .get(index)
                .copied()
                .flatten()
                .ok_or(Error::Missing)?,
        )
    }
    pub fn focused(&self) -> Option<usize> {
        self.desktop.view().focused.map(|id| usize::from(id.slot))
    }
    pub fn switch_window(&mut self) -> Result<(), Error> {
        self.desktop.switch(self.shell, false)?;
        Ok(())
    }
    pub fn bounds(&self, index: usize) -> Result<Bounds, Error> {
        let w = self.desktop.window(
            self.ids
                .get(index)
                .copied()
                .flatten()
                .ok_or(Error::Missing)?,
        )?;
        Ok(Bounds {
            x: w.bounds.x,
            y: w.bounds.y,
            width: w.bounds.width,
            height: w.bounds.height,
        })
    }
    pub fn geometry(&mut self, index: usize, mut bounds: Bounds) -> Result<Bounds, Error> {
        // Files needs a visible name field and at least two metadata rows.
        // Other bounded app layouts retain their existing minimum geometry.
        bounds.width = bounds.width.clamp(if index == 0 { 160 } else { 120 }, 320);
        bounds.height = bounds.height.clamp(if index == 0 { 100 } else { 80 }, 180);
        let r = self.desktop.geometry(
            self.shell,
            self.ids
                .get(index)
                .copied()
                .flatten()
                .ok_or(Error::Missing)?,
            to_rect(bounds),
        )?;
        Ok(Bounds {
            x: r.x,
            y: r.y,
            width: r.width,
            height: r.height,
        })
    }
    pub fn layer(&mut self, layer: Layer) -> Result<(), Error> {
        self.desktop.set_layer(self.shell, layer)
    }
    pub fn hit(&self, x: i32, y: i32) -> Option<(usize, bool)> {
        for id in self.desktop.view().windows.into_iter().rev().flatten() {
            let Ok(w) = self.desktop.window(id) else {
                continue;
            };
            if !w.visible {
                continue;
            }
            let outer = Rect {
                x: w.bounds.x,
                y: w.bounds.y - 11,
                width: w.bounds.width,
                height: w.bounds.height + 11,
            };
            if outer.contains(x, y) {
                return Some((usize::from(id.slot), y < w.bounds.y));
            }
        }
        None
    }
    pub fn next_scene(&mut self) -> Result<u64, Error> {
        self.scene = self
            .scene
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Exhausted)?;
        Ok(self.scene)
    }
}
fn to_rect(bounds: Bounds) -> Rect {
    Rect {
        x: bounds.x,
        y: bounds.y,
        width: bounds.width,
        height: bounds.height,
    }
}
