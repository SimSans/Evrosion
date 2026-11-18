//! Original-volume projection and expected consent only. These functions mint
//! no endpoint, owner presence, namespace or capability. Native Root must still
//! authenticate the service/recipient, re-inspect, present, confirm and retire.
use ev_userspace_contract::workspace::{Entry, EntryState, Kind, Name, ObjectId};
use ev_workspace_service::{control, legacy};
use ev_workspace_shell::{ActionScope, ActionTarget, Effect, Owner, ProtectedKind, Rights};

pub fn kind(object: legacy::Object) -> ProtectedKind {
    match object {
        legacy::Object::Notes => ProtectedKind::PickerConsent,
        legacy::Object::Private => ProtectedKind::OwnerOverride,
    }
}
pub fn entry(object: legacy::Object, metadata: legacy::Metadata) -> Option<Entry> {
    if metadata.identity != legacy::Identity::for_object(object)
        || (control::LegacyResponse {
            request_id: 1,
            lease_epoch: 1,
            status: control::Status::Applied,
            metadata: Some(metadata),
        })
        .encode()
        .is_err()
    {
        return None;
    }
    Some(Entry {
        object: metadata.identity.projected_object,
        parent: ObjectId {
            slot: 0,
            generation: 1,
        },
        revision: metadata.counter,
        size: metadata.length,
        kind: Kind::File,
        state: EntryState::Live,
        name: Name::new(match object {
            legacy::Object::Notes => b"Notes",
            legacy::Object::Private => b"Private",
        })
        .ok()?,
    })
}
pub fn scope(
    object: legacy::Object,
    metadata: legacy::Metadata,
    requester: Owner,
) -> Option<ActionScope> {
    let entry = entry(object, metadata)?;
    if !requester.valid() {
        return None;
    }
    Some(ActionScope {
        kind: kind(object),
        requester,
        target: ActionTarget::Object {
            dataset: metadata.identity.volume,
            slot: entry.object.slot,
            generation: entry.object.generation,
            revision: entry.revision,
        },
        rights: Rights::READ,
    })
}
pub fn matches_effect(
    object: legacy::Object,
    metadata: legacy::Metadata,
    requester: Owner,
    effect: &Effect,
) -> bool {
    scope(object, metadata, requester) == Some(effect.scope())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Actor, Identity, policy::Policy};
    fn metadata(object: legacy::Object) -> legacy::Metadata {
        legacy::Metadata {
            identity: legacy::Identity::for_object(object),
            counter: 0,
            length: 0,
            digest: [9; 32],
            global_operation: 0,
        }
    }
    fn effect(scope: ActionScope) -> Effect {
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
        let app = Identity {
            process: 5,
            thread: 6,
            registered: 1,
        };
        let mut p = Policy::new(shell, root).unwrap();
        p.install(
            1,
            Actor {
                control: 9,
                identity: app,
                ready: true,
                mapping_epoch: 1,
                failed: false,
            },
        )
        .unwrap();
        let a = p.trusted.attest_attention(&mut p.desktop, 1).unwrap();
        let c = p.trusted.challenge(&mut p.desktop, a, scope).unwrap();
        let v = p
            .trusted
            .attest_presented(&mut p.desktop, c, scope, 1, 2)
            .unwrap();
        p.trusted
            .attest_confirmation(
                &mut p.desktop,
                v,
                scope,
                3,
                ev_workspace_shell::ConfirmationSource::Physical,
            )
            .unwrap()
    }
    #[test]
    fn matching_numbers_cannot_alias_new_dataset_or_ordinary_private_consent() {
        let m = metadata(legacy::Object::Private);
        let who = Owner {
            process: 5,
            incarnation: 1,
        };
        let expected = scope(legacy::Object::Private, m, who).unwrap();
        let mut ordinary = expected;
        ordinary.kind = ProtectedKind::PickerConsent;
        assert!(!matches_effect(
            legacy::Object::Private,
            m,
            who,
            &effect(ordinary)
        ));
        let mut other = expected;
        other.target = ActionTarget::Object {
            dataset: [0x84; 16],
            slot: 2,
            generation: 1,
            revision: 0,
        };
        assert!(!matches_effect(
            legacy::Object::Private,
            m,
            who,
            &effect(other)
        ));
        let approved = effect(expected);
        assert!(matches_effect(legacy::Object::Private, m, who, &approved));
        let mut changed = m;
        changed.counter = 1;
        changed.global_operation = 1;
        assert!(!matches_effect(
            legacy::Object::Private,
            changed,
            who,
            &approved
        ));
        assert!(!matches_effect(
            legacy::Object::Private,
            m,
            Owner {
                process: 7,
                incarnation: 1
            },
            &approved
        ));
    }
    #[test]
    fn original_zero_counter_is_preserved_and_wrong_volume_or_pending_counter_cannot_project() {
        let m = metadata(legacy::Object::Notes);
        let e = entry(legacy::Object::Notes, m).unwrap();
        assert_eq!((e.object.slot, e.object.generation, e.revision), (1, 1, 0));
        let mut wrong = m;
        wrong.identity.volume = [0x84; 16];
        assert!(entry(legacy::Object::Notes, wrong).is_none());
        let mut wrong = m;
        wrong.counter = 1;
        assert!(entry(legacy::Object::Notes, wrong).is_none());
        assert!(entry(legacy::Object::Private, m).is_none());
    }
}
