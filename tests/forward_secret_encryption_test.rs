use std::collections::BTreeSet;

use topo::event_modules::forward_secret::{
    message_ciphertext_commitment, public_key_for_private, root_commitment, ForwardSecretProjector,
    FsEvent, HistoryCoord, NodePrefix, RecipientKind, WrapKey,
};
use topo::pipeline::{event_id, EventId, WorkspaceId};

fn id(label: &str) -> EventId {
    event_id(label.as_bytes())
}

fn workspace() -> WorkspaceId {
    id("workspace")
}

fn private(label: &str) -> [u8; 32] {
    id(label)
}

fn root(label: &str) -> [u8; 32] {
    id(label)
}

fn coord(minute: u64, label: &str) -> HistoryCoord {
    HistoryCoord {
        unix_minute: minute,
        event_id: id(label),
    }
}

fn recipient(recipient_id: EventId) -> FsEvent {
    FsEvent::RecipientCreated {
        workspace_id: workspace(),
        recipient_id,
        kind: RecipientKind::Device,
    }
}

fn invite_recipient(recipient_id: EventId) -> FsEvent {
    FsEvent::RecipientCreated {
        workspace_id: workspace(),
        recipient_id,
        kind: RecipientKind::Invite,
    }
}

fn pubkey(recipient_id: EventId, prev_pubkey_id: Option<EventId>, key_label: &str) -> FsEvent {
    FsEvent::DevicePubkey {
        workspace_id: workspace(),
        recipient_id,
        prev_pubkey_id,
        public_key: public_key_for_private(private(key_label)),
    }
}

fn epoch(
    prev_epoch_id: Option<EventId>,
    removed_recipient_id: Option<EventId>,
    root_label: &str,
) -> FsEvent {
    FsEvent::KeyEpoch {
        workspace_id: workspace(),
        prev_epoch_id,
        removed_recipient_id,
        root_commitment: root_commitment(root(root_label)),
    }
}

fn message(epoch_id: EventId, minute: u64, label: &str) -> FsEvent {
    let coord = coord(minute, label);
    FsEvent::MessageEncrypted {
        workspace_id: workspace(),
        epoch_id,
        coord,
        ciphertext_commitment: message_ciphertext_commitment(epoch_id, coord, id(label)),
    }
}

fn delete(epoch_id: EventId, coords: Vec<HistoryCoord>) -> FsEvent {
    FsEvent::HistoryDelete {
        workspace_id: workspace(),
        epoch_id,
        deleted_coords: coords,
    }
}

fn apply_all(projector: &mut ForwardSecretProjector, events: impl IntoIterator<Item = FsEvent>) {
    for event in events {
        projector.apply_event(event, 0);
    }
}

fn converge(projector: &mut ForwardSecretProjector, fuel: usize) {
    for _ in 0..2048 {
        let generated = projector.derive_events(fuel).emitted_events;
        if generated.is_empty() {
            return;
        }
        for event in generated {
            projector.apply_event(event, 0);
        }
    }
    panic!("forward-secret projector did not converge");
}

fn converge_recording(projector: &mut ForwardSecretProjector, fuel: usize) -> Vec<FsEvent> {
    let mut recorded = Vec::new();
    for _ in 0..2048 {
        let generated = projector.derive_events(fuel).emitted_events;
        if generated.is_empty() {
            return recorded;
        }
        for event in generated {
            recorded.push(event.clone());
            projector.apply_event(event, 0);
        }
    }
    panic!("forward-secret projector did not converge");
}

#[test]
fn out_of_order_tombstones_and_removals_still_converge() {
    let alice = id("alice-ooo");
    let alice_key_v1 = pubkey(alice, None, "alice-ooo-key-v1");
    let alice_key_v1_id = alice_key_v1.event_id();
    let alice_key_v2 = pubkey(alice, Some(alice_key_v1_id), "alice-ooo-key-v2");
    let alice_key_v2_id = alice_key_v2.event_id();
    let first_epoch = epoch(None, Some(alice), "ooo-root");
    let first_epoch_id = first_epoch.event_id();

    let mut projector = ForwardSecretProjector::default();
    apply_all(
        &mut projector,
        [alice_key_v2, first_epoch, alice_key_v1, recipient(alice)],
    );
    projector.insert_local_epoch_root(first_epoch_id, root("ooo-root"));
    converge(&mut projector, 32);

    let snapshot = projector.public_snapshot();
    assert!(!snapshot.active_pubkeys.contains(&(alice, alice_key_v1_id)));
    assert!(!snapshot.active_pubkeys.contains(&(alice, alice_key_v2_id)));
    assert!(!snapshot
        .wraps
        .iter()
        .any(|wrap| wrap.epoch_id == first_epoch_id));
}

#[test]
fn partitioned_join_unknown_to_remover_gets_wrap_after_heal() {
    let alice = id("alice-partition");
    let bob = id("bob-partition");
    let cara = id("cara-partition");
    let alice_key = pubkey(alice, None, "alice-partition-key");
    let bob_key = pubkey(bob, None, "bob-partition-key");
    let cara_key = pubkey(cara, None, "cara-partition-key");
    let alice_key_id = alice_key.event_id();
    let bob_key_id = bob_key.event_id();
    let cara_key_id = cara_key.event_id();
    let removal_epoch = epoch(None, Some(bob), "partition-removal-root");
    let removal_epoch_id = removal_epoch.event_id();

    let mut partitioned_rotator = ForwardSecretProjector::default();
    apply_all(
        &mut partitioned_rotator,
        [
            recipient(alice),
            recipient(bob),
            alice_key.clone(),
            bob_key.clone(),
            removal_epoch.clone(),
        ],
    );
    partitioned_rotator.insert_local_epoch_root(removal_epoch_id, root("partition-removal-root"));
    converge(&mut partitioned_rotator, 32);

    let before_heal = partitioned_rotator.public_snapshot();
    assert!(before_heal.wraps.contains(&WrapKey {
        epoch_id: removal_epoch_id,
        pubkey_id: alice_key_id,
        node_prefix: NodePrefix::ROOT,
    }));
    assert!(!before_heal.wraps.contains(&WrapKey {
        epoch_id: removal_epoch_id,
        pubkey_id: bob_key_id,
        node_prefix: NodePrefix::ROOT,
    }));
    assert!(!before_heal.wraps.contains(&WrapKey {
        epoch_id: removal_epoch_id,
        pubkey_id: cara_key_id,
        node_prefix: NodePrefix::ROOT,
    }));

    partitioned_rotator.apply_event(recipient(cara), 0);
    partitioned_rotator.apply_event(cara_key.clone(), 0);
    converge(&mut partitioned_rotator, 32);

    let mut all_at_once = ForwardSecretProjector::default();
    apply_all(
        &mut all_at_once,
        [
            recipient(cara),
            cara_key,
            removal_epoch,
            bob_key,
            recipient(bob),
            alice_key,
            recipient(alice),
        ],
    );
    all_at_once.insert_local_epoch_root(removal_epoch_id, root("partition-removal-root"));
    converge(&mut all_at_once, 32);

    let healed = partitioned_rotator.public_snapshot();
    assert!(healed.wraps.contains(&WrapKey {
        epoch_id: removal_epoch_id,
        pubkey_id: cara_key_id,
        node_prefix: NodePrefix::ROOT,
    }));
    assert!(!healed.wraps.contains(&WrapKey {
        epoch_id: removal_epoch_id,
        pubkey_id: bob_key_id,
        node_prefix: NodePrefix::ROOT,
    }));
    assert_eq!(healed, all_at_once.public_snapshot());
}

#[test]
fn pubkey_tombstones_receipts_and_removal_frontier_drive_wraps() {
    let alice = id("alice");
    let bob = id("bob");
    let cara = id("cara");

    let alice_key = pubkey(alice, None, "alice-key");
    let bob_key_v1 = pubkey(bob, None, "bob-key-v1");
    let cara_key = pubkey(cara, None, "cara-key");
    let alice_key_id = alice_key.event_id();
    let bob_key_v1_id = bob_key_v1.event_id();
    let cara_key_id = cara_key.event_id();
    let first_epoch = epoch(None, None, "epoch-1-root");
    let first_epoch_id = first_epoch.event_id();

    let mut projector = ForwardSecretProjector::default();
    apply_all(
        &mut projector,
        [
            recipient(alice),
            recipient(bob),
            recipient(cara),
            alice_key,
            bob_key_v1,
            cara_key,
            first_epoch,
        ],
    );
    projector.insert_local_epoch_root(first_epoch_id, root("epoch-1-root"));
    converge(&mut projector, 32);

    let initial_wraps = projector.public_snapshot().wraps;
    assert_eq!(initial_wraps.len(), 3);
    assert!(initial_wraps.contains(&WrapKey {
        epoch_id: first_epoch_id,
        pubkey_id: alice_key_id,
        node_prefix: NodePrefix::ROOT,
    }));
    assert!(initial_wraps.contains(&WrapKey {
        epoch_id: first_epoch_id,
        pubkey_id: bob_key_v1_id,
        node_prefix: NodePrefix::ROOT,
    }));
    assert!(initial_wraps.contains(&WrapKey {
        epoch_id: first_epoch_id,
        pubkey_id: cara_key_id,
        node_prefix: NodePrefix::ROOT,
    }));

    let bob_key_v2 = pubkey(bob, Some(bob_key_v1_id), "bob-key-v2");
    let bob_key_v2_id = bob_key_v2.event_id();
    projector.apply_event(bob_key_v2, 0);
    converge(&mut projector, 32);

    let after_rotation = projector.public_snapshot();
    assert!(after_rotation
        .active_pubkeys
        .contains(&(bob, bob_key_v2_id)));
    assert!(!after_rotation
        .active_pubkeys
        .contains(&(bob, bob_key_v1_id)));
    assert!(after_rotation.wraps.contains(&WrapKey {
        epoch_id: first_epoch_id,
        pubkey_id: bob_key_v2_id,
        node_prefix: NodePrefix::ROOT,
    }));

    projector.insert_local_private_key(alice_key_id, private("alice-key"));
    converge(&mut projector, 32);
    assert!(projector.public_snapshot().receipts.contains(&WrapKey {
        epoch_id: first_epoch_id,
        pubkey_id: alice_key_id,
        node_prefix: NodePrefix::ROOT,
    }));

    let second_epoch = epoch(Some(first_epoch_id), Some(cara), "epoch-2-root");
    let second_epoch_id = second_epoch.event_id();
    projector.apply_event(second_epoch, 0);
    projector.insert_local_epoch_root(second_epoch_id, root("epoch-2-root"));
    converge(&mut projector, 32);

    let after_removal = projector.public_snapshot();
    assert!(!after_removal
        .active_pubkeys
        .iter()
        .any(|(recipient, _)| *recipient == cara));
    assert!(after_removal.wraps.contains(&WrapKey {
        epoch_id: second_epoch_id,
        pubkey_id: alice_key_id,
        node_prefix: NodePrefix::ROOT,
    }));
    assert!(after_removal.wraps.contains(&WrapKey {
        epoch_id: second_epoch_id,
        pubkey_id: bob_key_v2_id,
        node_prefix: NodePrefix::ROOT,
    }));
    assert!(!after_removal.wraps.contains(&WrapKey {
        epoch_id: second_epoch_id,
        pubkey_id: cara_key_id,
        node_prefix: NodePrefix::ROOT,
    }));
}

#[test]
fn purged_pubkey_blocks_post_compromise_recovery_from_canonical_events() {
    let alice = id("alice-fs");
    let alice_key_v1 = pubkey(alice, None, "alice-fs-key-v1");
    let alice_key_v1_id = alice_key_v1.event_id();
    let first_epoch = epoch(None, None, "fs-root");
    let first_epoch_id = first_epoch.event_id();
    let deleted_coord = coord(60, "fs-deleted");
    let deleted_message = message(first_epoch_id, 60, "fs-deleted");

    let mut canonical_events = vec![
        recipient(alice),
        alice_key_v1.clone(),
        first_epoch.clone(),
        deleted_message,
    ];
    let mut live = ForwardSecretProjector::default();
    apply_all(&mut live, canonical_events.clone());
    live.insert_local_epoch_root(first_epoch_id, root("fs-root"));
    canonical_events.extend(converge_recording(&mut live, 32));

    live.insert_local_private_key(alice_key_v1_id, private("alice-fs-key-v1"));
    canonical_events.extend(converge_recording(&mut live, 32));

    let alice_key_v2 = pubkey(alice, Some(alice_key_v1_id), "alice-fs-key-v2");
    canonical_events.push(alice_key_v2.clone());
    live.apply_event(alice_key_v2, 0);
    canonical_events.extend(converge_recording(&mut live, 32));

    assert!(live
        .public_snapshot()
        .purged_pubkeys
        .contains(&alice_key_v1_id));

    let delete_event = delete(first_epoch_id, vec![deleted_coord]);
    canonical_events.push(delete_event.clone());
    live.apply_event(delete_event, 0);
    assert!(!live.can_decrypt(first_epoch_id, deleted_coord));

    let mut attacker_after_purge = ForwardSecretProjector::default();
    apply_all(&mut attacker_after_purge, canonical_events.clone());
    attacker_after_purge.insert_local_private_key(alice_key_v1_id, private("alice-fs-key-v1"));
    assert!(!attacker_after_purge.can_recover_material(first_epoch_id, deleted_coord));

    let canonical_without_purge = canonical_events
        .into_iter()
        .filter(|event| !matches!(event, FsEvent::PubkeyPurged { .. }))
        .collect::<Vec<_>>();
    let mut attacker_before_purge = ForwardSecretProjector::default();
    apply_all(&mut attacker_before_purge, canonical_without_purge);
    attacker_before_purge.insert_local_private_key(alice_key_v1_id, private("alice-fs-key-v1"));
    assert!(attacker_before_purge.can_recover_material(first_epoch_id, deleted_coord));
}

#[test]
fn bounded_wrap_expansion_converges_to_the_same_state_as_unbounded_expansion() {
    let first_epoch = epoch(None, None, "large-root");
    let first_epoch_id = first_epoch.event_id();
    let mut base_events = vec![first_epoch];
    for index in 0..37 {
        let recipient_id = id(&format!("recipient-{index}"));
        base_events.push(recipient(recipient_id));
        base_events.push(pubkey(
            recipient_id,
            None,
            &format!("recipient-{index}-key"),
        ));
    }

    let mut bounded = ForwardSecretProjector::default();
    let mut unbounded = ForwardSecretProjector::default();
    apply_all(&mut bounded, base_events.clone());
    apply_all(&mut unbounded, base_events);
    bounded.insert_local_epoch_root(first_epoch_id, root("large-root"));
    unbounded.insert_local_epoch_root(first_epoch_id, root("large-root"));

    converge(&mut bounded, 5);
    converge(&mut unbounded, 256);

    assert_eq!(bounded.public_snapshot(), unbounded.public_snapshot());
    assert_eq!(bounded.public_snapshot().wraps.len(), 37);
}

#[test]
fn replay_order_duplicates_and_delete_order_converge_to_identical_public_state() {
    let alice = id("alice-order");
    let bob = id("bob-order");
    let alice_key = pubkey(alice, None, "alice-order-key");
    let bob_key = pubkey(bob, None, "bob-order-key");
    let first_epoch = epoch(None, None, "order-root");
    let first_epoch_id = first_epoch.event_id();
    let msg_a = message(first_epoch_id, 10, "order-a");
    let msg_b = message(first_epoch_id, 11, "order-b");
    let msg_c = message(first_epoch_id, 12, "order-c");
    let delete_b = delete(first_epoch_id, vec![coord(11, "order-b")]);

    let order_a = vec![
        recipient(alice),
        recipient(bob),
        alice_key.clone(),
        bob_key.clone(),
        first_epoch.clone(),
        msg_a.clone(),
        msg_b.clone(),
        msg_c.clone(),
        delete_b.clone(),
        delete_b.clone(),
    ];
    let order_b = vec![
        delete_b,
        msg_c,
        first_epoch,
        bob_key,
        recipient(bob),
        msg_b,
        alice_key,
        recipient(alice),
        msg_a,
    ];

    let mut a = ForwardSecretProjector::default();
    let mut b = ForwardSecretProjector::default();
    apply_all(&mut a, order_a);
    apply_all(&mut b, order_b);
    a.insert_local_epoch_root(first_epoch_id, root("order-root"));
    b.insert_local_epoch_root(first_epoch_id, root("order-root"));
    converge(&mut a, 2);
    converge(&mut b, 9);

    assert_eq!(a.public_snapshot(), b.public_snapshot());
}

#[test]
fn history_deletes_puncture_local_tree_material_commutatively() {
    let first_epoch = epoch(None, None, "history-root");
    let first_epoch_id = first_epoch.event_id();
    let coords = [
        coord(20, "history-a"),
        coord(21, "history-b"),
        coord(22, "history-c"),
        coord(23, "history-d"),
    ];

    let mut left = ForwardSecretProjector::default();
    let mut right = ForwardSecretProjector::default();
    apply_all(&mut left, [first_epoch.clone()]);
    apply_all(&mut right, [first_epoch]);
    left.insert_local_epoch_root(first_epoch_id, root("history-root"));
    right.insert_local_epoch_root(first_epoch_id, root("history-root"));

    for (index, coord) in coords.iter().enumerate() {
        left.apply_event(
            message(
                first_epoch_id,
                20 + index as u64,
                &format!("history-{}", (b'a' + index as u8) as char),
            ),
            0,
        );
        right.apply_event(
            message(
                first_epoch_id,
                20 + index as u64,
                &format!("history-{}", (b'a' + index as u8) as char),
            ),
            0,
        );
        assert!(left.can_decrypt(first_epoch_id, *coord));
        assert!(right.can_decrypt(first_epoch_id, *coord));
    }

    left.apply_event(delete(first_epoch_id, vec![coords[1], coords[2]]), 0);
    left.apply_event(delete(first_epoch_id, vec![coords[2]]), 0);
    right.apply_event(delete(first_epoch_id, vec![coords[2]]), 0);
    right.apply_event(delete(first_epoch_id, vec![coords[1], coords[2]]), 0);

    assert_eq!(
        left.retained_cover(first_epoch_id),
        right.retained_cover(first_epoch_id)
    );
    assert_eq!(
        left.purge_cover(first_epoch_id),
        right.purge_cover(first_epoch_id)
    );
    assert!(left.can_decrypt(first_epoch_id, coords[0]));
    assert!(!left.can_decrypt(first_epoch_id, coords[1]));
    assert!(!left.can_decrypt(first_epoch_id, coords[2]));
    assert!(left.can_decrypt(first_epoch_id, coords[3]));
}

#[test]
fn invite_history_grant_covers_undeleted_history_and_excludes_deleted_coordinates() {
    let invite = id("invite-recipient");
    let first_epoch = epoch(None, None, "invite-root");
    let first_epoch_id = first_epoch.event_id();
    let kept_a = coord(30, "invite-a");
    let deleted_b = coord(31, "invite-b");
    let kept_c = coord(32, "invite-c");
    let late_unknown = coord(33, "invite-late-unknown");

    let mut projector = ForwardSecretProjector::default();
    apply_all(
        &mut projector,
        [
            invite_recipient(invite),
            first_epoch,
            message(first_epoch_id, 30, "invite-a"),
            message(first_epoch_id, 31, "invite-b"),
            message(first_epoch_id, 32, "invite-c"),
            delete(first_epoch_id, vec![deleted_b]),
        ],
    );
    projector.insert_local_epoch_root(first_epoch_id, root("invite-root"));

    let grant = projector.invite_history_grant(workspace(), invite, first_epoch_id);
    let retained = projector.retained_cover(first_epoch_id);
    let grant_cover = match &grant {
        FsEvent::InviteHistoryGrant { retained_cover, .. } => {
            retained_cover.iter().copied().collect::<BTreeSet<_>>()
        }
        _ => unreachable!("expected invite grant"),
    };

    assert_eq!(grant_cover, retained);
    assert!(projector.grant_allows(&grant, kept_a));
    assert!(!projector.grant_allows(&grant, deleted_b));
    assert!(projector.grant_allows(&grant, kept_c));
    assert!(projector.grant_allows(&grant, late_unknown));

    projector.apply_event(message(first_epoch_id, 33, "invite-late-unknown"), 0);
    assert!(projector.can_decrypt(first_epoch_id, late_unknown));
}
