use super::*;

fn owner(process: u64) -> Owner {
    Owner {
        process,
        incarnation: 1,
    }
}
fn surface(object: u64) -> Surface {
    Surface {
        object,
        generation: 1,
    }
}
fn rect(x: i32, y: i32, width: u32, height: u32) -> Rect {
    Rect {
        x,
        y,
        width,
        height,
    }
}
const SHELL: Owner = Owner {
    process: 1,
    incarnation: 1,
};
const TRUSTED: Owner = Owner {
    process: 2,
    incarnation: 1,
};
fn empty() -> (Desktop, TrustedAdapter) {
    Desktop::new(SHELL, TRUSTED, rect(0, 0, 1024, 768)).unwrap()
}
fn four() -> (Desktop, TrustedAdapter, [WindowId; 4]) {
    let (mut desktop, adapter) = empty();
    let kinds = [
        WindowKind::Files,
        WindowKind::EditorOne,
        WindowKind::EditorTwo,
        WindowKind::Inspector,
    ];
    let geometry = [
        rect(0, 0, 400, 300),
        rect(100, 80, 400, 300),
        rect(200, 160, 400, 300),
        rect(700, 200, 250, 300),
    ];
    let ids = core::array::from_fn(|at| {
        desktop
            .install(
                kinds[at],
                owner(11 + at as u64),
                surface(101 + at as u64),
                geometry[at],
            )
            .unwrap()
    });
    (desktop, adapter, ids)
}
fn nodes(bounds: Rect, protected: bool) -> [Node; 4] {
    let base = Node {
        local: 1,
        parent: None,
        role: Role::Window,
        label: Label::new("Workspace window").unwrap(),
        bounds,
        value: Value::None,
        actions: Actions::NONE,
        disabled: false,
        protected: false,
    };
    [
        base,
        Node {
            local: 2,
            parent: Some(1),
            role: Role::TextBox,
            label: Label::new("Document text").unwrap(),
            bounds: rect(bounds.x + 5, bounds.y + 5, 20, 20),
            value: Value::TextRange {
                revision: 8,
                offset: 4096,
                length: 4096,
                total: 1024 * 1024,
            },
            actions: Actions::one(Action::Activate).union(Actions::one(Action::Focus)),
            protected,
            ..base
        },
        Node {
            local: 3,
            parent: Some(1),
            role: Role::Dialog,
            bounds: rect(bounds.x + 50, bounds.y + 50, 200, 100),
            ..base
        },
        Node {
            local: 4,
            parent: Some(3),
            role: Role::Button,
            label: Label::new("Keep editing").unwrap(),
            bounds: rect(bounds.x + 60, bounds.y + 60, 80, 30),
            actions: Actions::one(Action::Activate),
            ..base
        },
    ]
}
fn publish(desktop: &mut Desktop, id: WindowId, protected: bool) {
    let window = *desktop.window(id).unwrap();
    let tree = Tree::new(window.view_revision + 1, &nodes(window.bounds, protected)).unwrap();
    desktop
        .publish_view(window.owner, id, tree.revision(), tree)
        .unwrap();
}
fn scope(desktop: &Desktop, id: WindowId) -> ActionScope {
    let owner = desktop.window(id).unwrap().owner;
    ActionScope {
        kind: ProtectedKind::OwnerOverride,
        requester: owner,
        target: ActionTarget::Window { id, owner },
        rights: Rights::PROCESS_CONTROL.union(Rights::DELEGATE),
    }
}
fn presented(
    desktop: &mut Desktop,
    adapter: &mut TrustedAdapter,
    scope: ActionScope,
    serial: u64,
    frame: u64,
) -> (Challenge, PresentedWitness) {
    let attention = adapter.attest_attention(desktop, serial).unwrap();
    let challenge = adapter.challenge(desktop, attention, scope).unwrap();
    let witness = adapter
        .attest_presented(desktop, challenge, scope, frame, serial + 5)
        .unwrap();
    (challenge, witness)
}

#[test]
fn four_independent_owners_route_focus_and_refuse_app_focus_theft() {
    let (mut desktop, _, ids) = four();
    assert_eq!(desktop.view().windows, ids.map(Some));
    let selected = desktop.pointer_target(SHELL, 150, 100).unwrap().unwrap();
    assert_eq!(
        (selected.window, selected.owner, selected.surface),
        (ids[1], owner(12), surface(102))
    );
    assert_eq!(desktop.keyboard_target(SHELL).unwrap(), Some(selected));
    let before = desktop.view();
    assert_eq!(desktop.activate(owner(13), ids[2]), Err(Error::Owner));
    assert_eq!(desktop.view(), before);
    desktop.activate(SHELL, ids[2]).unwrap();
    assert_eq!(desktop.validate_delivery(selected), Err(Error::Stale));
    assert_eq!(
        desktop.keyboard_target(SHELL).unwrap().unwrap().owner,
        owner(13)
    );
    assert_eq!(desktop.switch(SHELL, true).unwrap(), Some(ids[1]));
}

#[test]
fn resize_clamps_geometry_and_cannot_publish_old_pixel_bounds() {
    let (mut desktop, _, ids) = four();
    publish(&mut desktop, ids[1], false);
    let moved = desktop
        .geometry(SHELL, ids[1], rect(-500, 900, 4000, 200))
        .unwrap();
    assert_eq!(moved, rect(0, 568, 1024, 200));
    let provider = desktop.provider(owner(80), ProviderRights::READ).unwrap();
    assert!(matches!(
        desktop.semantic(owner(80), provider, ids[1]),
        Err(Error::Unsettled)
    ));
    let old_bounds = Tree::new(2, &nodes(rect(100, 80, 400, 300), false)).unwrap();
    assert_eq!(
        desktop.publish_view(owner(12), ids[1], 2, old_bounds),
        Err(Error::Geometry)
    );
    let before = desktop.view();
    assert_eq!(
        desktop.geometry(SHELL, ids[1], rect(i32::MAX, 0, 10, 10)),
        Err(Error::Geometry)
    );
    assert_eq!(desktop.view(), before);
}

#[test]
fn shell_replacement_keeps_apps_surfaces_trees_and_rejects_old_routing() {
    let (mut desktop, mut adapter, ids) = four();
    for id in ids {
        publish(&mut desktop, id, false);
    }
    desktop.activate(SHELL, ids[1]).unwrap();
    let old = ids.map(|id| *desktop.window(id).unwrap());
    let action = scope(&desktop, ids[1]);
    let (_, witness) = presented(&mut desktop, &mut adapter, action, 10, 1);
    let replacement = Owner {
        process: SHELL.process,
        incarnation: 2,
    };
    desktop.replace_shell(SHELL, replacement).unwrap();
    assert_eq!(ids.map(|id| *desktop.window(id).unwrap()), old);
    assert_eq!(desktop.keyboard_target(SHELL), Err(Error::Owner));
    assert_eq!(
        desktop
            .keyboard_target(replacement)
            .unwrap()
            .unwrap()
            .window,
        ids[1]
    );
    assert_eq!(
        adapter.attest_confirmation(
            &mut desktop,
            witness,
            action,
            20,
            ConfirmationSource::Physical
        ),
        Err(Error::Stale)
    );
    // Independent attention can be entered without a normal Shell message.
    assert!(adapter.attest_attention(&mut desktop, 21).is_ok());
}

#[test]
fn owner_retirement_and_reuse_never_retarget_queued_input_or_semantic_ids() {
    let (mut desktop, _, ids) = four();
    desktop.activate(SHELL, ids[1]).unwrap();
    let old = desktop.keyboard_target(SHELL).unwrap().unwrap();
    let mut previous = ids[1];
    for incarnation in 2..=65 {
        let old_owner = desktop.window(previous).unwrap().owner;
        desktop.retire(previous, old_owner).unwrap();
        let replacement = Owner {
            process: 12,
            incarnation,
        };
        let id = desktop
            .install(
                WindowKind::EditorOne,
                replacement,
                Surface {
                    object: 102,
                    generation: incarnation,
                },
                rect(100, 80, 400, 300),
            )
            .unwrap();
        assert!(id.generation > previous.generation);
        assert_eq!(desktop.window(previous), Err(Error::Stale));
        assert_eq!(
            desktop.publish_view(
                old_owner,
                id,
                1,
                Tree::new(1, &nodes(rect(100, 80, 400, 300), false)).unwrap()
            ),
            Err(Error::Owner)
        );
        previous = id;
    }
    assert_eq!(desktop.validate_delivery(old), Err(Error::Stale));
    assert_eq!(desktop.view().windows.iter().flatten().count(), 4);
}

#[test]
fn modal_surface_and_semantic_subtree_have_one_current_owner() {
    let (mut desktop, _, ids) = four();
    publish(&mut desktop, ids[1], false);
    desktop.activate(SHELL, ids[1]).unwrap();
    let before = desktop.keyboard_target(SHELL).unwrap().unwrap();
    let modal = Modal {
        node: 3,
        surface: surface(500),
        bounds: rect(150, 130, 200, 100),
    };
    assert_eq!(
        desktop.modal(owner(13), ids[1], Some(modal)),
        Err(Error::Owner)
    );
    desktop.modal(owner(12), ids[1], Some(modal)).unwrap();
    assert_eq!(desktop.validate_delivery(before), Err(Error::Stale));
    let target = desktop.keyboard_target(SHELL).unwrap().unwrap();
    assert_eq!(
        (target.owner, target.surface, target.modal),
        (owner(12), surface(500), Some(3))
    );
    assert_eq!(desktop.pointer_target(SHELL, 110, 100), Err(Error::Modal));
    let provider = desktop
        .provider(
            owner(80),
            ProviderRights::READ.union(ProviderRights::ACTION),
        )
        .unwrap();
    assert_eq!(
        desktop.semantic_action(
            owner(80),
            provider,
            NodeId {
                window: ids[1],
                local: 2
            },
            1,
            Action::Activate
        ),
        Err(Error::Modal)
    );
    let delivery = desktop
        .semantic_action(
            owner(80),
            provider,
            NodeId {
                window: ids[1],
                local: 4,
            },
            1,
            Action::Activate,
        )
        .unwrap();
    assert_eq!(
        (
            delivery.owner,
            delivery.target,
            delivery.view_revision,
            delivery.action
        ),
        (
            owner(12),
            NodeId {
                window: ids[1],
                local: 4
            },
            1,
            Action::Activate
        )
    );
    desktop.dispatch_semantic(owner(80), delivery).unwrap();
    desktop.modal(owner(12), ids[1], None).unwrap();
    assert_eq!(desktop.validate_delivery(target), Err(Error::Stale));
}

#[test]
fn semantic_publication_is_atomic_and_requires_matching_present_revision() {
    let (mut desktop, _, ids) = four();
    publish(&mut desktop, ids[1], false);
    let provider = desktop.provider(owner(80), ProviderRights::READ).unwrap();
    let before = desktop.revision();
    let tree = Tree::new(2, &nodes(desktop.window(ids[1]).unwrap().bounds, false)).unwrap();
    assert_eq!(
        desktop.publish_view(owner(12), ids[1], 1, tree),
        Err(Error::Revision)
    );
    assert_eq!(desktop.revision(), before);
    let view = desktop.semantic(owner(80), provider, ids[1]).unwrap();
    assert_eq!((view.displayed_revision, view.tree.revision()), (1, 1));
    desktop.publish_view(owner(12), ids[1], 2, tree).unwrap();
    assert_eq!(
        desktop
            .semantic(owner(80), provider, ids[1])
            .unwrap()
            .tree
            .revision(),
        2
    );
    let mut cyclic = nodes(desktop.window(ids[1]).unwrap().bounds, false);
    cyclic[1].parent = Some(4);
    assert_eq!(Tree::new(3, &cyclic), Err(Error::Tree));
}

#[test]
fn provider_replacement_revokes_old_actions_and_assistive_focus_is_distinct() {
    let (mut desktop, _, ids) = four();
    publish(&mut desktop, ids[1], false);
    publish(&mut desktop, ids[2], false);
    desktop.activate(SHELL, ids[1]).unwrap();
    let provider = desktop
        .provider(
            owner(80),
            ProviderRights::READ.union(ProviderRights::ACTION),
        )
        .unwrap();
    let node = NodeId {
        window: ids[2],
        local: 2,
    };
    desktop
        .assistive_focus(owner(80), provider, node, 1)
        .unwrap();
    assert_eq!(
        desktop.keyboard_target(SHELL).unwrap().unwrap().window,
        ids[1]
    );
    assert_eq!(desktop.assistive_focus_node(), Some(node));
    let focus = desktop
        .semantic_action(owner(80), provider, node, 1, Action::Focus)
        .unwrap();
    desktop.dispatch_semantic(owner(80), focus).unwrap();
    assert_eq!(
        desktop.dispatch_semantic(owner(80), focus),
        Err(Error::Stale)
    );
    assert_eq!(desktop.keyboard_focus(), Some(node));
    assert_eq!(
        desktop.keyboard_target(SHELL).unwrap().unwrap().owner,
        owner(13)
    );
    publish(&mut desktop, ids[2], false);
    assert_eq!(
        desktop.semantic_action(owner(80), provider, node, 1, Action::Activate),
        Err(Error::Revision)
    );
    let replacement = desktop
        .provider(
            Owner {
                process: 80,
                incarnation: 2,
            },
            ProviderRights::READ,
        )
        .unwrap();
    assert_eq!(desktop.assistive_focus_node(), None);
    assert_eq!(
        desktop.semantic_action(owner(80), provider, node, 2, Action::Activate),
        Err(Error::Denied)
    );
    assert_eq!(
        desktop.semantic_action(replacement.owner(), replacement, node, 2, Action::Activate),
        Err(Error::Denied)
    );
    desktop.revoke_provider(replacement).unwrap();
    assert!(matches!(
        desktop.semantic(replacement.owner(), replacement, ids[2]),
        Err(Error::Denied)
    ));
}

#[test]
fn ordinary_semantic_activate_and_layer_selection_cannot_create_consent() {
    let (mut desktop, _, ids) = four();
    publish(&mut desktop, ids[1], true);
    let provider = desktop
        .provider(
            owner(80),
            ProviderRights::READ.union(ProviderRights::ACTION),
        )
        .unwrap();
    let windows = ids.map(|id| *desktop.window(id).unwrap());
    for layer in [Layer::Simple, Layer::Advanced, Layer::AbsoluteAccess] {
        desktop.set_layer(SHELL, layer).unwrap();
        assert_eq!(desktop.pending_challenge(), None);
        assert_eq!(ids.map(|id| *desktop.window(id).unwrap()), windows);
        assert_eq!(
            desktop.semantic_action(
                owner(80),
                provider,
                NodeId {
                    window: ids[1],
                    local: 2
                },
                1,
                Action::Activate
            ),
            Err(Error::Protected)
        );
    }
}

#[test]
fn protected_confirmation_requires_fresh_input_after_completed_frame_barrier() {
    let (mut desktop, mut adapter, ids) = four();
    let action = scope(&desktop, ids[1]);
    let (_, witness) = presented(&mut desktop, &mut adapter, action, 10, 1);
    assert_eq!(desktop.keyboard_target(SHELL), Err(Error::Protected));
    assert_eq!(desktop.activate(SHELL, ids[2]), Err(Error::Protected));
    assert_eq!(
        adapter.attest_confirmation(
            &mut desktop,
            witness,
            action,
            14,
            ConfirmationSource::Physical
        ),
        Err(Error::Stale)
    );
    let (challenge, witness) = presented(&mut desktop, &mut adapter, action, 20, 2);
    let effect = adapter
        .attest_confirmation(
            &mut desktop,
            witness,
            action,
            26,
            ConfirmationSource::Physical,
        )
        .unwrap();
    assert_eq!((effect.scope(), effect.nonce()), (action, challenge.nonce));
    assert!(!desktop.view().trusted_attention);
    assert_eq!(desktop.pending_challenge(), None);
    assert!(desktop.keyboard_target(SHELL).is_ok());
}

#[test]
fn current_target_rights_and_adapter_binding_are_required_for_witnesses() {
    let (mut desktop, mut adapter, ids) = four();
    let action = scope(&desktop, ids[1]);
    let attention = adapter.attest_attention(&mut desktop, 10).unwrap();
    let challenge = adapter.challenge(&mut desktop, attention, action).unwrap();
    let changed = ActionScope {
        rights: Rights::READ,
        ..action
    };
    assert!(matches!(
        adapter.attest_presented(&mut desktop, challenge, changed, 1, 15),
        Err(Error::Stale)
    ));
    let witness = adapter
        .attest_presented(&mut desktop, challenge, action, 1, 15)
        .unwrap();
    let (_, mut unrelated_adapter) = empty();
    assert_eq!(
        unrelated_adapter.attest_confirmation(
            &mut desktop,
            witness,
            action,
            16,
            ConfirmationSource::Physical
        ),
        Err(Error::Owner)
    );
    let (_, witness) = presented(&mut desktop, &mut adapter, action, 20, 2);
    desktop.retire(ids[1], owner(12)).unwrap();
    assert_eq!(
        adapter.attest_confirmation(
            &mut desktop,
            witness,
            action,
            26,
            ConfirmationSource::Physical
        ),
        Err(Error::Stale)
    );
}

#[test]
fn assistive_protected_path_needs_current_provider_and_actual_adapter_confirmation() {
    let (mut desktop, mut adapter, ids) = four();
    let old = desktop
        .provider(
            owner(80),
            ProviderRights::READ.union(ProviderRights::ACTION),
        )
        .unwrap();
    let action = scope(&desktop, ids[1]);
    let (_, witness) = presented(&mut desktop, &mut adapter, action, 10, 1);
    let metadata = desktop.protected_semantic(owner(80), old).unwrap();
    assert_eq!(metadata.challenge.scope, action);
    assert!(metadata.confirm_requires_adapter_witness);
    let replacement_owner = Owner {
        process: 80,
        incarnation: 2,
    };
    let replacement = desktop
        .provider(
            replacement_owner,
            ProviderRights::READ
                .union(ProviderRights::ACTION)
                .union(ProviderRights::CONFIRM),
        )
        .unwrap();
    assert_eq!(
        adapter.attest_confirmation(
            &mut desktop,
            witness,
            action,
            16,
            ConfirmationSource::Assistive {
                sender: owner(80),
                provider: old
            }
        ),
        Err(Error::Stale)
    );
    let (_, witness) = presented(&mut desktop, &mut adapter, action, 20, 2);
    assert_eq!(
        adapter.attest_confirmation(
            &mut desktop,
            witness,
            action,
            26,
            ConfirmationSource::Assistive {
                sender: owner(80),
                provider: old
            }
        ),
        Err(Error::Denied)
    );
    let (_, witness) = presented(&mut desktop, &mut adapter, action, 30, 3);
    let effect = adapter
        .attest_confirmation(
            &mut desktop,
            witness,
            action,
            36,
            ConfirmationSource::Assistive {
                sender: replacement_owner,
                provider: replacement,
            },
        )
        .unwrap();
    assert_eq!(effect.scope(), action);
}

#[test]
fn malformed_or_duplicate_admission_and_large_range_overflow_change_no_state() {
    let (mut desktop, _) = empty();
    assert_eq!(
        desktop
            .install(
                WindowKind::Files,
                owner(11),
                surface(101),
                rect(0, 0, 400, 300)
            )
            .unwrap()
            .generation,
        1
    );
    let before = desktop.view();
    assert_eq!(
        desktop.install(
            WindowKind::EditorOne,
            owner(12),
            surface(101),
            rect(0, 0, 400, 300)
        ),
        Err(Error::Duplicate)
    );
    assert_eq!(
        desktop.install(
            WindowKind::EditorOne,
            Owner {
                process: 0,
                incarnation: 1
            },
            surface(102),
            rect(0, 0, 400, 300)
        ),
        Err(Error::Identity)
    );
    assert_eq!(desktop.view(), before);
    let mut malformed = nodes(rect(0, 0, 400, 300), false);
    malformed[1].value = Value::TextRange {
        revision: 3,
        offset: u64::MAX,
        length: 1,
        total: u64::MAX,
    };
    assert_eq!(Tree::new(1, &malformed), Err(Error::Tree));
    assert_eq!(Label::new("bad\nlabel"), Err(Error::Text));
}

#[test]
fn queued_semantic_delivery_is_fenced_by_provider_replacement_and_view_publication() {
    let (mut desktop, _, ids) = four();
    publish(&mut desktop, ids[1], false);
    let provider = desktop
        .provider(
            owner(80),
            ProviderRights::READ.union(ProviderRights::ACTION),
        )
        .unwrap();
    let node = NodeId {
        window: ids[1],
        local: 2,
    };
    let queued = desktop
        .semantic_action(owner(80), provider, node, 1, Action::Activate)
        .unwrap();
    let replacement = desktop
        .provider(
            owner(81),
            ProviderRights::READ.union(ProviderRights::ACTION),
        )
        .unwrap();
    assert_eq!(
        desktop.dispatch_semantic(owner(80), queued),
        Err(Error::Denied)
    );
    let queued = desktop
        .semantic_action(owner(81), replacement, node, 1, Action::Activate)
        .unwrap();
    publish(&mut desktop, ids[1], false);
    assert_eq!(
        desktop.dispatch_semantic(owner(81), queued),
        Err(Error::Stale)
    );
    let current = desktop
        .semantic_action(owner(81), replacement, node, 2, Action::Activate)
        .unwrap();
    desktop.dispatch_semantic(owner(81), current).unwrap();
    assert_eq!(
        desktop.dispatch_semantic(owner(81), current),
        Err(Error::Stale)
    );
}

#[test]
fn object_rename_revision_or_rights_change_cannot_reuse_a_presented_consent() {
    let (mut desktop, mut adapter, _) = four();
    let action = ActionScope {
        kind: ProtectedKind::PickerConsent,
        requester: owner(12),
        target: ActionTarget::Object {
            dataset: [8; 16],
            slot: 17,
            generation: 9,
            revision: 23,
        },
        rights: Rights::EDIT,
    };
    let (_, witness) = presented(&mut desktop, &mut adapter, action, 10, 1);
    let renamed = ActionScope {
        target: ActionTarget::Object {
            dataset: [8; 16],
            slot: 17,
            generation: 9,
            revision: 24,
        },
        ..action
    };
    assert_eq!(
        adapter.attest_confirmation(
            &mut desktop,
            witness,
            renamed,
            16,
            ConfirmationSource::Physical
        ),
        Err(Error::Stale)
    );
    let (_, witness) = presented(&mut desktop, &mut adapter, action, 20, 2);
    let widened = ActionScope {
        rights: Rights::EDIT.union(Rights::REMOVE),
        ..action
    };
    assert_eq!(
        adapter.attest_confirmation(
            &mut desktop,
            witness,
            widened,
            26,
            ConfirmationSource::Physical
        ),
        Err(Error::Stale)
    );
}

#[test]
fn protected_or_disabled_dialog_cannot_be_bypassed_through_an_enabled_child() {
    let (mut desktop, _, ids) = four();
    let bounds = desktop.window(ids[1]).unwrap().bounds;
    let mut semantic = nodes(bounds, false);
    semantic[2].protected = true;
    desktop
        .publish_view(owner(12), ids[1], 1, Tree::new(1, &semantic).unwrap())
        .unwrap();
    let provider = desktop
        .provider(
            owner(80),
            ProviderRights::READ.union(ProviderRights::ACTION),
        )
        .unwrap();
    let child = NodeId {
        window: ids[1],
        local: 4,
    };
    assert_eq!(
        desktop.semantic_action(owner(80), provider, child, 1, Action::Activate),
        Err(Error::Protected)
    );
    semantic[2].protected = false;
    semantic[2].disabled = true;
    desktop
        .publish_view(owner(12), ids[1], 2, Tree::new(2, &semantic).unwrap())
        .unwrap();
    assert_eq!(
        desktop.semantic_action(owner(80), provider, child, 2, Action::Activate),
        Err(Error::Denied)
    );
    let incorrect = Modal {
        node: 3,
        surface: surface(500),
        bounds: rect(150, 130, 200, 99),
    };
    assert_eq!(
        desktop.modal(owner(12), ids[1], Some(incorrect)),
        Err(Error::Modal)
    );
}

#[test]
fn root_metadata_scope_and_protected_confirm_opt_in_are_separate() {
    let (mut desktop, mut adapter, ids) = four();
    let root_scope = ActionScope {
        kind: ProtectedKind::OwnerOverride,
        requester: owner(14),
        target: ActionTarget::ProtectedRoot {
            owner: TRUSTED,
            thread: 77,
            mapping_epoch: 9,
        },
        rights: Rights::SEMANTIC_READ.union(Rights::SEMANTIC_ACTION),
    };
    let (_, witness) = presented(&mut desktop, &mut adapter, root_scope, 10, 1);
    let widened = ActionScope {
        rights: root_scope.rights.union(Rights::ASSISTIVE_CONFIRM),
        ..root_scope
    };
    assert_eq!(
        adapter.attest_confirmation(
            &mut desktop,
            witness,
            widened,
            16,
            ConfirmationSource::Physical
        ),
        Err(Error::Stale)
    );
    let attention = adapter.attest_attention(&mut desktop, 20).unwrap();
    assert_eq!(
        adapter.challenge(
            &mut desktop,
            attention,
            ActionScope {
                target: ActionTarget::ProtectedRoot {
                    owner: owner(12),
                    thread: 77,
                    mapping_epoch: 9
                },
                ..root_scope
            }
        ),
        Err(Error::Owner)
    );
    for (at, rights) in [
        ProviderRights::READ,
        ProviderRights::READ.union(ProviderRights::ACTION),
    ]
    .into_iter()
    .enumerate()
    {
        let provider = desktop.provider(owner(80), rights).unwrap();
        let action = scope(&desktop, ids[1]);
        let serial = 30 + at as u64 * 10;
        let (_, witness) = presented(&mut desktop, &mut adapter, action, serial, 2 + at as u64);
        assert_eq!(
            adapter.attest_confirmation(
                &mut desktop,
                witness,
                action,
                serial + 6,
                ConfirmationSource::Assistive {
                    sender: owner(80),
                    provider
                }
            ),
            Err(Error::Denied)
        );
    }
}

#[test]
fn native_keyboard_node_is_atomic_with_tree_and_cannot_claim_another_root_focused_window() {
    let (mut desktop, _, ids) = four();
    desktop.activate(SHELL, ids[1]).unwrap();
    let target = *desktop.window(ids[2]).unwrap();
    let tree = Tree::new(1, &nodes(target.bounds, false)).unwrap();
    let before = desktop.view();
    assert_eq!(
        desktop.publish_presented_view(target.owner, target.id, 1, tree, Some(2)),
        Err(Error::Focus)
    );
    assert_eq!(desktop.view(), before);
    assert!(desktop.window(target.id).unwrap().tree.is_none());
    let focused = *desktop.window(ids[1]).unwrap();
    let tree = Tree::new(1, &nodes(focused.bounds, false)).unwrap();
    desktop
        .publish_presented_view(focused.owner, focused.id, 1, tree, Some(2))
        .unwrap();
    assert_eq!(
        desktop.keyboard_focus(),
        Some(NodeId {
            window: focused.id,
            local: 2
        })
    );
    assert_eq!(desktop.window(focused.id).unwrap().view_revision, 1);
    let tree = Tree::new(2, &nodes(focused.bounds, false)).unwrap();
    desktop
        .publish_presented_view(focused.owner, focused.id, 2, tree, None)
        .unwrap();
    assert_eq!(desktop.keyboard_focus(), None);
}
