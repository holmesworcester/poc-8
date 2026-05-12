//! Transit wrap commands.
//!
//! This is the active boundary between connection state and network bytes. It
//! accepts explicit endpoint keys and connection context, then returns opaque
//! transit bytes. It does not admit events or mutate schema; event admission and
//! transit out decide what to do with the result.

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::identity::endpoint::types::EndpointKeypair;

use crate::core::crypto;
use crate::protocol::event_modules::identity::invite;
use crate::protocol::event_modules::types::EventId;

use super::super::types::ConnectionId;
use super::codec;
use super::types::{
    TransitEnvelope, BOOTSTRAP_PURPOSE, CONNECTION_PURPOSE, INVITE_BOOTSTRAP_PURPOSE,
};

/// Plaintext byte budget for one transit batch. The cap is the inner plaintext,
/// not the wire frame; per-event length-prefix overhead is included by the
/// caller via the `inner_size` closure passed to `batch_inner_events`.
pub const TRANSIT_TARGET_PLAINTEXT_BYTES: usize = 32 * 1024 * 1024;

/// Per-event length-prefix overhead written by the inner-event codec. Callers
/// that bin-pack transit items must include this in their plaintext accounting.
pub const PER_EVENT_PLAINTEXT_OVERHEAD: usize = 4;

/// Greedily groups `items` into batches whose summed `inner_size` stays at or
/// below `TRANSIT_TARGET_PLAINTEXT_BYTES`. Items whose own `inner_size` already
/// exceeds the cap are emitted in their own single-item batch — the caller
/// decides whether to reject oversize inputs upstream.
pub fn batch_inner_events<T, F>(items: Vec<T>, inner_size: F) -> Vec<Vec<T>>
where
    F: Fn(&T) -> usize,
{
    let mut batches: Vec<Vec<T>> = Vec::new();
    let mut current: Vec<T> = Vec::new();
    let mut current_bytes = 0usize;
    for item in items {
        let item_bytes = inner_size(&item);
        if !current.is_empty()
            && current_bytes.saturating_add(item_bytes) > TRANSIT_TARGET_PLAINTEXT_BYTES
        {
            batches.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current_bytes = current_bytes.saturating_add(item_bytes);
        current.push(item);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

pub fn create_bootstrap(
    local: &EndpointKeypair,
    recipient_endpoint: EndpointId,
    inner: &[u8],
) -> Result<Vec<u8>, String> {
    // Bootstrap frames are addressed directly to an endpoint because a
    // connection id does not exist yet.
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let envelope = TransitEnvelope::Bootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext: Vec::new(),
    };
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        &local.secret,
        &recipient_endpoint,
        BOOTSTRAP_PURPOSE,
        &codec::associated_data(&envelope),
        &nonce,
        inner,
    )?;
    Ok(codec::encode(&TransitEnvelope::Bootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext,
    }))
}

pub fn create_invite_bootstrap_batch(
    local: &EndpointKeypair,
    recipient_endpoint: EndpointId,
    bootstrap_secret: &[u8; 32],
    workspace_id: EventId,
    invite_event_id: EventId,
    inners: Vec<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    // Invite bootstrap is deliberately not an endpoint X25519 handshake. The
    // copied invite secret is the authority, and the envelope binds it to one
    // workspace/invite pair before any inner canonical bytes are admitted.
    let bootstrap_hash = invite::types::bootstrap_secret_hash(bootstrap_secret);
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let envelope = TransitEnvelope::InviteBootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        bootstrap_hash,
        workspace_id,
        invite_event_id,
        nonce,
        ciphertext: Vec::new(),
    };
    let associated_data = codec::associated_data(&envelope);
    let key =
        crypto::hkdf_sha256_key(bootstrap_secret, INVITE_BOOTSTRAP_PURPOSE, &associated_data)?;
    let plaintext = codec::encode_inner_events(&inners)?;
    let ciphertext = crypto::xchacha20poly1305_encrypt(&key, &associated_data, &nonce, &plaintext)?;
    Ok(codec::encode(&TransitEnvelope::InviteBootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        bootstrap_hash,
        workspace_id,
        invite_event_id,
        nonce,
        ciphertext,
    }))
}

pub fn create_connection_batch(
    local: &EndpointKeypair,
    recipient_endpoint: EndpointId,
    connection_id: ConnectionId,
    inners: Vec<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    // Ordinary frames bind sender, recipient, and connection id into the
    // authenticated envelope before encrypting the inner event bytes. The
    // plaintext is a small fixed-format list so one transit envelope can carry a
    // coherent batch of canonical events without making TCP understand them.
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let envelope = TransitEnvelope::Connection {
        connection_id,
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext: Vec::new(),
    };
    let plaintext = codec::encode_inner_events(&inners)?;
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        &local.secret,
        &recipient_endpoint,
        CONNECTION_PURPOSE,
        &codec::associated_data(&envelope),
        &nonce,
        &plaintext,
    )?;
    Ok(codec::encode(&TransitEnvelope::Connection {
        connection_id,
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_size(n: &usize) -> usize {
        *n
    }

    #[test]
    fn empty_input_emits_no_batches() {
        let batches = batch_inner_events(Vec::<usize>::new(), identity_size);
        assert!(batches.is_empty());
    }

    #[test]
    fn single_item_under_cap_is_one_batch() {
        let batches = batch_inner_events(vec![10usize], identity_size);
        assert_eq!(batches, vec![vec![10usize]]);
    }

    #[test]
    fn items_summing_under_cap_stay_in_one_batch() {
        let batches = batch_inner_events(vec![1usize, 2, 3, 4], identity_size);
        assert_eq!(batches, vec![vec![1usize, 2, 3, 4]]);
    }

    #[test]
    fn exact_cap_fit_is_one_batch() {
        let batches = batch_inner_events(
            vec![TRANSIT_TARGET_PLAINTEXT_BYTES / 2, TRANSIT_TARGET_PLAINTEXT_BYTES / 2],
            identity_size,
        );
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 2);
    }

    #[test]
    fn item_that_would_cross_cap_starts_a_new_batch() {
        let half = TRANSIT_TARGET_PLAINTEXT_BYTES / 2;
        let over_half = half + 1;
        let batches = batch_inner_events(vec![half, over_half], identity_size);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0], vec![half]);
        assert_eq!(batches[1], vec![over_half]);
    }

    #[test]
    fn oversize_single_item_is_emitted_in_its_own_batch() {
        let oversize = TRANSIT_TARGET_PLAINTEXT_BYTES + 1;
        let batches = batch_inner_events(vec![oversize], identity_size);
        assert_eq!(batches, vec![vec![oversize]]);
    }

    #[test]
    fn oversize_first_item_does_not_swallow_following_items() {
        let oversize = TRANSIT_TARGET_PLAINTEXT_BYTES + 1;
        let batches = batch_inner_events(vec![oversize, 5], identity_size);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0], vec![oversize]);
        assert_eq!(batches[1], vec![5]);
    }

    #[test]
    fn each_item_above_half_cap_forces_one_item_per_batch() {
        // Any pair sums to more than the cap, so the greedy packer must emit
        // one batch per item without dropping or merging any.
        let big = TRANSIT_TARGET_PLAINTEXT_BYTES / 2 + 1;
        let batches = batch_inner_events(vec![big, big, big], identity_size);
        assert_eq!(batches.len(), 3);
        for batch in &batches {
            assert_eq!(batch.len(), 1);
            assert_eq!(batch[0], big);
        }
    }

    #[test]
    fn per_event_overhead_is_accounted_when_caller_includes_it() {
        // Two items each at exactly half the cap fit by raw byte length, but
        // adding PER_EVENT_PLAINTEXT_OVERHEAD per item pushes the pair over.
        let half = TRANSIT_TARGET_PLAINTEXT_BYTES / 2;
        let items = vec![half, half];
        let batches =
            batch_inner_events(items, |n| PER_EVENT_PLAINTEXT_OVERHEAD.saturating_add(*n));
        assert_eq!(batches.len(), 2);
    }
}
