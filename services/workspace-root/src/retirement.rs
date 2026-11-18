//! Correlation for a cooperative release acknowledgment. This is protocol
//! state only: it cannot construct a Kernel drain or physical loan receipt.
use crate::Identity;
use ev_userspace_contract::workspace::{DatasetId, Entry, EntryState, Kind};
use ev_workspace_shell::{ActionScope, ActionTarget, ProtectedKind, Rights};

/// Expected descriptor only, never a retirement receipt. The native adapter
/// supplies its immutable installed selection and separately retained actual
/// ProcessCONTROL, lease epoch and managed nonce; it then revalidates them.
pub fn file_scope(
    dataset: DatasetId,
    entry: Entry,
    recipient: Identity,
    writable: bool,
) -> Option<ActionScope> {
    if dataset.0 == [0; 16]
        || !recipient.valid()
        || entry.kind != Kind::File
        || entry.state != EntryState::Live
        || matches!(entry.object.generation, 0 | u64::MAX)
        || entry.revision == u64::MAX
    {
        return None;
    }
    Some(ActionScope {
        kind: ProtectedKind::Revoke,
        requester: crate::policy::owner(recipient),
        target: ActionTarget::Object {
            dataset: dataset.0,
            slot: entry.object.slot,
            generation: entry.object.generation,
            revision: entry.revision,
        },
        rights: if writable {
            Rights::READ.union(Rights::EDIT)
        } else {
            Rights::READ
        },
    })
}
pub struct ReleaseWait {
    identity: Identity,
    nonce: u32,
    by: u64,
    acknowledged: bool,
}
impl ReleaseWait {
    pub fn new(identity: Identity, nonce: u32, by: u64) -> Option<Self> {
        if !identity.valid() || matches!(nonce, 0 | u32::MAX) || matches!(by, 0 | u64::MAX) {
            return None;
        }
        Some(Self {
            identity,
            nonce,
            by,
            acknowledged: false,
        })
    }
    pub const fn nonce(&self) -> u32 {
        self.nonce
    }
    pub const fn acknowledged(&self) -> bool {
        self.acknowledged
    }
    pub fn observe(&mut self, actual: Identity, nonce: u32, now: u64) -> bool {
        if self.acknowledged || actual != self.identity || nonce != self.nonce || now >= self.by {
            return false;
        }
        self.acknowledged = true;
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_owner_nonce_original_cut_and_single_ack_are_required() {
        let id = Identity {
            process: 0x100000001,
            thread: 0x200000001,
            registered: 3,
        };
        let mut wait = ReleaseWait::new(id, 7, 100).unwrap();
        for wrong in [
            Identity { process: 1, ..id },
            Identity { thread: 1, ..id },
            Identity {
                registered: 4,
                ..id
            },
        ] {
            assert!(!wait.observe(wrong, 7, 1));
        }
        assert!(!wait.observe(id, 6, 1));
        assert!(!wait.observe(id, 7, 100));
        assert!(wait.observe(id, 7, 99));
        assert!(!wait.observe(id, 7, 99));
        assert!(wait.acknowledged());
        assert!(ReleaseWait::new(id, u32::MAX, 100).is_none());
    }

    fn entry() -> Entry {
        use ev_userspace_contract::workspace::{Name, ObjectId};
        Entry {
            object: ObjectId {
                slot: 2,
                generation: 1,
            },
            parent: ObjectId {
                slot: 0,
                generation: 1,
            },
            revision: 0,
            size: 224,
            kind: Kind::File,
            state: EntryState::Live,
            name: Name::new(b"Private").unwrap(),
        }
    }
    fn recipient() -> Identity {
        Identity {
            process: 5,
            thread: 6,
            registered: 1,
        }
    }
    fn policy() -> crate::policy::Policy {
        let root = Identity {
            process: 1,
            thread: 2,
            registered: 1,
        };
        let shell = Identity {
            process: 3,
            thread: 4,
            registered: 1,
        };
        let mut p = crate::policy::Policy::new(shell, root).unwrap();
        p.install(
            1,
            crate::Actor {
                control: 9,
                identity: recipient(),
                ready: true,
                mapping_epoch: 1,
                failed: false,
            },
        )
        .unwrap();
        p
    }

    #[test]
    fn recorded_private_revoke_requires_fresh_protected_confirmation_even_in_layer_one() {
        use ev_workspace_shell::{ConfirmationSource, Layer};
        let mut p = policy();
        assert_eq!(p.desktop.view().layer, Layer::Simple);
        let scope =
            file_scope(DatasetId(*b"EVRO-USERS-VOL01"), entry(), recipient(), false).unwrap();
        assert_eq!(scope.kind, ProtectedKind::Revoke);
        assert_eq!(scope.rights, Rights::READ);
        let a = p.trusted.attest_attention(&mut p.desktop, 10).unwrap();
        let c = p.trusted.challenge(&mut p.desktop, a, scope).unwrap();
        let witness = p
            .trusted
            .attest_presented(&mut p.desktop, c, scope, 1, 20)
            .unwrap();
        assert!(
            p.trusted
                .attest_confirmation(
                    &mut p.desktop,
                    witness,
                    scope,
                    20,
                    ConfirmationSource::Physical
                )
                .is_err()
        );
        // A stale/held input consumes no confirmation. Cancel, present the
        // exact scope again and require a genuinely later input boundary.
        p.trusted.cancel(&mut p.desktop).unwrap();
        let a = p.trusted.attest_attention(&mut p.desktop, 21).unwrap();
        let c = p.trusted.challenge(&mut p.desktop, a, scope).unwrap();
        let witness = p
            .trusted
            .attest_presented(&mut p.desktop, c, scope, 2, 22)
            .unwrap();
        let effect = p
            .trusted
            .attest_confirmation(
                &mut p.desktop,
                witness,
                scope,
                23,
                ConfirmationSource::Physical,
            )
            .unwrap();
        assert_eq!(effect.scope(), scope);
        assert!(p.desktop.pending_challenge().is_none());
        // This expected descriptor/effect is still not a Kernel drain receipt.
    }

    #[test]
    fn another_dataset_object_revision_owner_or_right_cannot_replace_the_presented_revoke() {
        use ev_workspace_shell::ConfirmationSource;
        let scope =
            file_scope(DatasetId(*b"EVRO-USERS-VOL01"), entry(), recipient(), false).unwrap();
        let mut alternate_entry = entry();
        alternate_entry.revision = 1;
        let mut other_object = entry();
        other_object.object.slot = 1;
        let mut other_generation = entry();
        other_generation.object.generation = 2;
        let alternatives = [
            file_scope(DatasetId([0x84; 16]), entry(), recipient(), false).unwrap(),
            file_scope(
                DatasetId(*b"EVRO-USERS-VOL01"),
                alternate_entry,
                recipient(),
                false,
            )
            .unwrap(),
            file_scope(
                DatasetId(*b"EVRO-USERS-VOL01"),
                other_object,
                recipient(),
                false,
            )
            .unwrap(),
            file_scope(
                DatasetId(*b"EVRO-USERS-VOL01"),
                other_generation,
                recipient(),
                false,
            )
            .unwrap(),
            file_scope(
                DatasetId(*b"EVRO-USERS-VOL01"),
                entry(),
                Identity {
                    process: 7,
                    ..recipient()
                },
                false,
            )
            .unwrap(),
            file_scope(DatasetId(*b"EVRO-USERS-VOL01"), entry(), recipient(), true).unwrap(),
        ];
        for changed in alternatives {
            let mut p = policy();
            let a = p.trusted.attest_attention(&mut p.desktop, 1).unwrap();
            let c = p.trusted.challenge(&mut p.desktop, a, scope).unwrap();
            let witness = p
                .trusted
                .attest_presented(&mut p.desktop, c, scope, 1, 2)
                .unwrap();
            assert!(
                p.trusted
                    .attest_confirmation(
                        &mut p.desktop,
                        witness,
                        changed,
                        3,
                        ConfirmationSource::Physical
                    )
                    .is_err()
            );
            assert_eq!(p.desktop.pending_challenge(), Some(c));
        }
        assert!(file_scope(DatasetId([0; 16]), entry(), recipient(), false).is_none());
        let mut directory = entry();
        directory.kind = Kind::Directory;
        assert!(file_scope(DatasetId([1; 16]), directory, recipient(), false).is_none());
    }

    #[test]
    fn ordinary_assistive_action_scope_cannot_confirm_a_revoke() {
        use ev_workspace_shell::{ConfirmationSource, ProviderRights};
        let mut p = policy();
        let sender = crate::policy::owner(recipient());
        let provider = p
            .desktop
            .provider(sender, ProviderRights::READ.union(ProviderRights::ACTION))
            .unwrap();
        let scope = file_scope(DatasetId([9; 16]), entry(), recipient(), false).unwrap();
        let a = p.trusted.attest_attention(&mut p.desktop, 1).unwrap();
        let c = p.trusted.challenge(&mut p.desktop, a, scope).unwrap();
        let witness = p
            .trusted
            .attest_presented(&mut p.desktop, c, scope, 1, 2)
            .unwrap();
        assert!(
            p.trusted
                .attest_confirmation(
                    &mut p.desktop,
                    witness,
                    scope,
                    3,
                    ConfirmationSource::Assistive { sender, provider }
                )
                .is_err()
        );
        assert_eq!(p.desktop.pending_challenge(), Some(c));
    }
}
