//! A1 native tuple/geometry projection into the unchanged Tree16 model.
//! These values are correlation metadata. The actual adapter must authenticate
//! caller/provider, query coherent Display acceptance and enforce scope first.
use ev_workspace_client::semantic as wire;
use ev_workspace_shell::{Action, Actions, Error, Label, Node, Rect, Role, Tree, Value};

/// An actual owner challenge binds every bit before the native grant exists.
/// The protected-confirmation opt-in is separate from ordinary ACTION.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scopes(u8);
impl Scopes {
    pub const READ: u8 = 1;
    pub const ACTION: u8 = 2;
    pub const TEXT: u8 = 4;
    pub const CONFIRM: u8 = 8;
    pub fn new(bits: u8, protected_root: bool) -> Result<Self, Error> {
        if bits & !15 != 0
            || bits & Self::READ == 0
            || bits & Self::CONFIRM != 0 && (!protected_root || bits & Self::ACTION == 0)
        {
            return Err(Error::Denied);
        }
        Ok(Self(bits))
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub fn challenge_rights(self) -> ev_workspace_shell::Rights {
        use ev_workspace_shell::Rights;
        let mut rights = Rights::SEMANTIC_READ;
        if self.0 & Self::ACTION != 0 {
            rights = rights.union(Rights::SEMANTIC_ACTION);
        }
        if self.0 & Self::TEXT != 0 {
            rights = rights.union(Rights::SEMANTIC_TEXT);
        }
        if self.0 & Self::CONFIRM != 0 {
            rights = rights.union(Rights::ASSISTIVE_CONFIRM);
        }
        rights
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Presented {
    pub model: u64,
    pub view: u64,
    pub frame: u64,
    pub mapping_epoch: u64,
    pub width: u16,
    pub height: u16,
}
impl Presented {
    pub fn matches(self, header: wire::Header) -> bool {
        [self.model, self.view, self.frame, self.mapping_epoch]
            .iter()
            .all(|v| !matches!(*v, 0 | u64::MAX))
            && self.model == header.model
            && self.view == header.view
            && self.frame == header.frame
            && self.mapping_epoch == header.mapping_epoch
            && self.width == header.width
            && self.height == header.height
    }
}
fn role(value: wire::Role) -> Role {
    match value {
        wire::Role::Window => Role::Window,
        wire::Role::Dialog => Role::Dialog,
        wire::Role::Button => Role::Button,
        wire::Role::TextBox => Role::TextBox,
        wire::Role::Label => Role::Label,
        wire::Role::List => Role::List,
        wire::Role::ListItem => Role::ListItem,
        wire::Role::Document => Role::Document,
        wire::Role::Menu => Role::Menu,
        wire::Role::Slider => Role::Slider,
    }
}
fn actions(bits: u8) -> Result<Actions, Error> {
    if bits & !63 != 0 {
        return Err(Error::Denied);
    }
    let mut out = Actions::NONE;
    for (bit, action) in [
        Action::Activate,
        Action::Focus,
        Action::Select,
        Action::Scroll,
        Action::Expand,
        Action::SetValue,
    ]
    .into_iter()
    .enumerate()
    {
        if bits & (1 << bit) != 0 {
            out = out.union(Actions::one(action));
        }
    }
    Ok(out)
}
/// The internal publication serial remains consecutive. It is never substituted
/// for the actual source view/frame tuple retained by the native adapter.
pub fn project(
    snapshot: &wire::Snapshot,
    presented: Presented,
    bounds: Rect,
    publication: u64,
) -> Result<Tree, Error> {
    let header = snapshot.header();
    if !presented.matches(header)
        || bounds.width != u32::from(header.width)
        || bounds.height != u32::from(header.height)
        || !bounds.valid()
    {
        return Err(Error::Geometry);
    }
    let empty = Node {
        local: 0,
        parent: None,
        role: Role::Label,
        label: Label::new("")?,
        bounds,
        value: Value::None,
        actions: Actions::NONE,
        disabled: false,
        protected: false,
    };
    let mut nodes = [empty; 16];
    for (to, from) in nodes.iter_mut().zip(snapshot.nodes()) {
        *to = Node {
            local: from.local,
            parent: (from.parent != 0).then_some(from.parent),
            role: role(from.role),
            label: Label::new(from.label.as_str())?,
            bounds: Rect {
                x: bounds
                    .x
                    .checked_add(i32::from(from.bounds.x))
                    .ok_or(Error::Geometry)?,
                y: bounds
                    .y
                    .checked_add(i32::from(from.bounds.y))
                    .ok_or(Error::Geometry)?,
                width: u32::from(from.bounds.width),
                height: u32::from(from.bounds.height),
            },
            value: match from.value {
                wire::Value::None => Value::None,
                wire::Value::Number(n) => Value::Number(n),
                wire::Value::TextRange {
                    revision,
                    offset,
                    length,
                    total,
                } => Value::TextRange {
                    revision,
                    offset,
                    length,
                    total,
                },
            },
            actions: actions(from.actions)?,
            disabled: from.flags & 1 != 0,
            protected: from.flags & 2 != 0,
        };
    }
    Tree::new(publication, &nodes[..snapshot.nodes().len()])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_confirmation_requires_its_own_root_only_opt_in() {
        assert!(Scopes::new(1, false).is_ok());
        assert!(Scopes::new(3, false).is_ok());
        assert!(Scopes::new(9, true).is_err());
        assert!(Scopes::new(11, false).is_err());
        assert!(Scopes::new(0, true).is_err());
        assert!(Scopes::new(16, true).is_err());
        let metadata = Scopes::new(1, true).unwrap().challenge_rights();
        let actions = Scopes::new(3, true).unwrap().challenge_rights();
        let confirm = Scopes::new(11, true).unwrap().challenge_rights();
        assert_ne!(metadata, actions);
        assert_ne!(actions, confirm);
        assert_eq!(
            confirm.bits(),
            ev_workspace_shell::Rights::SEMANTIC_READ
                .union(ev_workspace_shell::Rights::SEMANTIC_ACTION)
                .union(ev_workspace_shell::Rights::ASSISTIVE_CONFIRM)
                .bits()
        );
    }
    #[test]
    fn exact_native_tuple_geometry_and_separate_publication_serial_are_required() {
        let header = wire::Header {
            nonce: 7,
            page: 0,
            pages: 1,
            model: 0x1_0000_0001,
            view: 0x2_0000_0002,
            frame: 0x3_0000_0003,
            mapping_epoch: 0x4_0000_0004,
            width: 320,
            height: 180,
            keyboard: 0,
            modal: 0,
        };
        let root = wire::Node {
            local: 1,
            parent: 0,
            role: wire::Role::Window,
            flags: 0,
            actions: 0,
            label: wire::Label::new("Editor").unwrap(),
            bounds: wire::Rect {
                x: 0,
                y: 0,
                width: 320,
                height: 180,
            },
            value: wire::Value::None,
        };
        let button = wire::Node {
            local: 16,
            parent: 1,
            role: wire::Role::Button,
            flags: 0,
            actions: 1,
            label: wire::Label::new("Open").unwrap(),
            bounds: wire::Rect {
                x: 5,
                y: 6,
                width: 30,
                height: 20,
            },
            value: wire::Value::None,
        };
        let mut snapshot = wire::Snapshot::EMPTY;
        snapshot.replace(header, &[root, button]).unwrap();
        let good = Presented {
            model: header.model,
            view: header.view,
            frame: header.frame,
            mapping_epoch: header.mapping_epoch,
            width: 320,
            height: 180,
        };
        let bounds = Rect {
            x: 320,
            y: 91,
            width: 320,
            height: 180,
        };
        let tree = project(&snapshot, good, bounds, 1).unwrap();
        assert_eq!(tree.revision(), 1);
        assert_eq!(snapshot.header().view, 0x2_0000_0002);
        assert_eq!(
            (
                tree.node(16).unwrap().bounds.x,
                tree.node(16).unwrap().bounds.y
            ),
            (325, 97)
        );
        for bad in [
            Presented { model: 1, ..good },
            Presented { view: 2, ..good },
            Presented { frame: 3, ..good },
            Presented {
                mapping_epoch: 4,
                ..good
            },
            Presented { width: 319, ..good },
        ] {
            assert!(project(&snapshot, bad, bounds, 1).is_err());
        }
        assert!(
            project(
                &snapshot,
                good,
                Rect {
                    width: 319,
                    ..bounds
                },
                1
            )
            .is_err()
        );
    }
}
