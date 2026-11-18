//! Independent bounded per-owner control queues. Only unsent desired scenes
//! coalesce; a partially accepted scene always finishes its exact low/high pair.
//! Accepted SEND means mailbox ownership, never consumed UI or completed pixels.
use crate::Identity;
use ev_workspace_client::ui::Command;
const PEERS: usize = 5;
const INPUTS: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scene {
    pub identity: Identity,
    pub model: u64,
    pub width: u16,
    pub height: u16,
    pub focused: bool,
    pub mapping_epoch: u32,
}
#[derive(Clone, Copy)]
struct Batch {
    scene: Scene,
    commands: [Option<Command>; 5],
    next: usize,
}
#[derive(Clone, Copy)]
struct Input {
    command: Command,
    model: u64,
}
#[derive(Clone, Copy)]
struct Peer {
    identity: Option<Identity>,
    configured: bool,
    current: Option<Batch>,
    desired: Option<Scene>,
    inputs: [Option<Input>; INPUTS],
    length: usize,
    last_model: u64,
}
impl Peer {
    const EMPTY: Self = Self {
        identity: None,
        configured: false,
        current: None,
        desired: None,
        inputs: [None; INPUTS],
        length: 0,
        last_model: 0,
    };
}
pub struct Outbox {
    peers: [Peer; PEERS],
}
impl Default for Outbox {
    fn default() -> Self {
        Self::new()
    }
}
impl Outbox {
    pub const fn new() -> Self {
        Self {
            peers: [Peer::EMPTY; PEERS],
        }
    }
    pub fn retire(&mut self, index: usize) {
        if let Some(peer) = self.peers.get_mut(index) {
            *peer = Peer::EMPTY;
        }
    }
    /// Unsent user input and partially submitted scene pairs still need their
    /// original delivery. This query does not coalesce, discard or acknowledge
    /// anything and proves no recipient/RPC completion.
    pub fn has_pending(&self) -> bool {
        self.peers
            .iter()
            .any(|peer| peer.current.is_some() || peer.desired.is_some() || peer.length != 0)
    }
    pub fn scene(&mut self, index: usize, scene: Scene) -> bool {
        let Some(peer) = self.peers.get_mut(index) else {
            return false;
        };
        if !scene.identity.valid()
            || scene.model == 0
            || scene.model == u64::MAX
            || matches!(scene.mapping_epoch, 0 | u32::MAX)
        {
            return false;
        }
        if peer.identity != Some(scene.identity) {
            *peer = Peer {
                identity: Some(scene.identity),
                ..Peer::EMPTY
            };
        }
        if scene.model <= peer.last_model
            || peer.current.is_some_and(|b| scene.model <= b.scene.model)
            || peer.desired.is_some_and(|old| scene.model <= old.model)
        {
            return false;
        }
        peer.desired = Some(scene);
        true
    }
    pub fn input(
        &mut self,
        index: usize,
        identity: Identity,
        model: u64,
        command: Command,
    ) -> bool {
        let Some(peer) = self.peers.get_mut(index) else {
            return false;
        };
        if peer.identity != Some(identity)
            || peer.length == INPUTS
            || model == 0
            || command.encode().is_err()
        {
            return false;
        }
        if !matches!(
            command,
            Command::Insert(_)
                | Command::Navigate { .. }
                | Command::Save
                | Command::SelectAll
                | Command::Close { .. }
                | Command::Scroll(_)
                | Command::Activate(_)
                | Command::InfoWord { .. }
        ) {
            return false;
        }
        peer.inputs[peer.length] = Some(Input { command, model });
        peer.length += 1;
        true
    }
    /// Release is a correlated protocol operation scoped to the actual owner,
    /// not ordinary input to a prior scene. It survives unrelated scene changes
    /// while replacement/retire still discards the old owner's entire queue.
    pub fn release(&mut self, index: usize, identity: Identity, command: Command) -> bool {
        let Some(peer) = self.peers.get_mut(index) else {
            return false;
        };
        if peer.identity != Some(identity)
            || peer.length == INPUTS
            || !matches!(command, Command::ReleaseFile { .. })
            || command.encode().is_err()
        {
            return false;
        }
        peer.inputs[peer.length] = Some(Input { command, model: 0 });
        peer.length += 1;
        true
    }
    fn promote(peer: &mut Peer, index: usize) {
        if peer.current.is_none()
            && let Some(scene) = peer.desired.take()
        {
            let shell = index == 4;
            peer.current = Some(Batch {
                scene,
                next: 0,
                commands: [
                    if peer.configured {
                        None
                    } else {
                        Some(Command::Configure {
                            instance: if shell { 0 } else { index as u8 + 1 },
                            mapping_epoch: scene.mapping_epoch,
                        })
                    },
                    if shell {
                        None
                    } else {
                        Some(Command::Resize {
                            width: scene.width,
                            height: scene.height,
                        })
                    },
                    if shell {
                        None
                    } else {
                        Some(Command::Focus(scene.focused))
                    },
                    Some(Command::ScenePart {
                        high: false,
                        word: scene.model as u32,
                    }),
                    Some(Command::ScenePart {
                        high: true,
                        word: (scene.model >> 32) as u32,
                    }),
                ],
            });
        }
    }
    pub fn next(&mut self, index: usize) -> Option<Command> {
        let peer = self.peers.get_mut(index)?;
        Self::promote(peer, index);
        if let Some(batch) = peer.current.as_mut() {
            while batch.next < 5 && batch.commands[batch.next].is_none() {
                batch.next += 1;
            }
            if batch.next < 5 {
                return batch.commands[batch.next];
            }
        }
        while peer.length > 0 {
            let front = peer.inputs[0].unwrap();
            if front.model == 0 || front.model == peer.last_model {
                return Some(front.command);
            }
            Self::pop(peer);
        }
        None
    }
    pub fn accepted(&mut self, index: usize) -> bool {
        let Some(peer) = self.peers.get_mut(index) else {
            return false;
        };
        if let Some(batch) = peer.current.as_mut() {
            if batch.next >= 5 || batch.commands[batch.next].is_none() {
                return false;
            }
            if matches!(batch.commands[batch.next], Some(Command::Configure { .. })) {
                peer.configured = true;
            }
            batch.next += 1;
            if batch.next == 5 {
                peer.last_model = batch.scene.model;
                peer.current = None;
            }
            return true;
        }
        if peer.length == 0 {
            return false;
        }
        Self::pop(peer);
        true
    }
    fn pop(peer: &mut Peer) {
        peer.inputs.copy_within(1..peer.length, 0);
        peer.length -= 1;
        peer.inputs[peer.length] = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scene(process: u64, model: u64) -> Scene {
        Scene {
            identity: Identity {
                process,
                thread: process + 1,
                registered: 1,
            },
            model,
            width: 320,
            height: 180,
            focused: false,
            mapping_epoch: 1,
        }
    }
    #[test]
    fn shutdown_pending_query_preserves_queued_text_and_partial_scene_pairs() {
        let mut out = Outbox::new();
        let s = scene(11, 1);
        assert!(!out.has_pending());
        assert!(out.scene(1, s));
        for _ in 0..4 {
            assert!(out.has_pending());
            out.next(1).unwrap();
            assert!(out.accepted(1));
        }
        assert!(out.has_pending());
        assert_eq!(
            out.next(1),
            Some(Command::ScenePart {
                high: true,
                word: 0
            })
        );
        assert!(out.has_pending());
        assert!(out.accepted(1));
        assert!(!out.has_pending());
        assert!(out.input(1, s.identity, 1, Command::Insert('x')));
        for _ in 0..3 {
            assert!(out.has_pending());
            assert_eq!(out.next(1), Some(Command::Insert('x')));
        }
        assert!(out.accepted(1));
        assert!(!out.has_pending());
    }
    #[test]
    fn blocked_shell_does_not_consume_other_owner_capacity_or_root_attention() {
        let mut out = Outbox::new();
        for index in 0..5 {
            assert!(out.scene(index, scene(10 + index as u64, 1)));
        }
        for model in 2..500 {
            assert!(out.scene(4, scene(14, model)));
        }
        assert!(matches!(
            out.next(4),
            Some(Command::Configure { instance: 0, .. })
        ));
        for _ in 0..5 {
            assert!(out.next(1).is_some());
            assert!(out.accepted(1));
        }
        assert!(out.input(1, scene(11, 1).identity, 1, Command::Insert('a')));
        assert_eq!(out.next(1), Some(Command::Insert('a')));
        // Shell remains at the same unaccepted Configure; no global queue fills.
        assert!(matches!(
            out.next(4),
            Some(Command::Configure { instance: 0, .. })
        ));
    }
    #[test]
    fn accepted_low_half_is_finished_before_new_desired_scene() {
        let mut out = Outbox::new();
        assert!(out.scene(0, scene(10, 0x1_0000_0001)));
        for _ in 0..4 {
            out.next(0).unwrap();
            assert!(out.accepted(0));
        }
        assert_eq!(
            out.next(0),
            Some(Command::ScenePart {
                high: true,
                word: 1
            })
        );
        assert!(out.scene(0, scene(10, 0x2_0000_0002)));
        assert_eq!(
            out.next(0),
            Some(Command::ScenePart {
                high: true,
                word: 1
            })
        );
        assert!(out.accepted(0));
        assert!(matches!(out.next(0), Some(Command::Resize { .. })));
    }
    #[test]
    fn replacement_and_model_change_drop_only_unsent_old_input() {
        let mut out = Outbox::new();
        let first = scene(10, 1);
        out.scene(0, first);
        for _ in 0..5 {
            out.next(0);
            out.accepted(0);
        }
        assert!(out.input(0, first.identity, 1, Command::Insert('x')));
        out.scene(0, scene(10, 2));
        for _ in 0..4 {
            out.next(0);
            out.accepted(0);
        }
        assert_eq!(out.next(0), None);
        assert!(!out.input(0, scene(99, 2).identity, 2, Command::Save));
        out.scene(0, scene(99, 3));
        assert!(matches!(out.next(0), Some(Command::Configure { .. })));
    }
    #[test]
    fn correlated_release_survives_scene_change_but_never_owner_replacement() {
        let mut out = Outbox::new();
        let first = scene(10, 1);
        out.scene(1, first);
        for _ in 0..5 {
            out.next(1);
            out.accepted(1);
        }
        let release = Command::ReleaseFile {
            nonce: 7,
            mode: ev_workspace_client::ui::ReleaseMode::KeepDocument,
        };
        assert!(!out.input(1, first.identity, 1, release));
        assert!(!out.release(1, first.identity, Command::Save));
        assert!(out.release(1, first.identity, release));
        out.scene(1, scene(10, 2));
        for _ in 0..4 {
            out.next(1);
            out.accepted(1);
        }
        assert_eq!(out.next(1), Some(release));
        out.scene(1, scene(99, 3));
        for _ in 0..5 {
            out.next(1);
            out.accepted(1);
        }
        assert_eq!(out.next(1), None);
    }
}
