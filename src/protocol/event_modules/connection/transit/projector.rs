//! Projector for inbound transit frames.
//!
//! Transit frames are not semantic facts. They are encrypted transport
//! envelopes around canonical inner event bytes. This projector is the strict
//! admission boundary for those envelopes: it receives one queued core network
//! row plus explicit local context, authenticates and decrypts the frame, and
//! emits `canonical.in` rows carrying the recovered inner bytes and provenance.
//!
//! The important invariant is that this projector never decides what the inner
//! bytes *mean*. It only proves how they arrived:
//!
//! ```text
//! core.network.inbound row
//!   + local endpoint secret for bootstrap frames
//!   + connection event for connection frames
//!   -> authenticated inner canonical bytes
//!   -> canonical.in rows with transit provenance
//! ```
//!
//! The next admission step classifies those inner bytes under the provenance:
//! endpoint bootstrap may only admit connection requests; invite bootstrap may
//! only admit shared identity facts for the invite workspace; connection transit
//! may admit connection-scoped sync events or shared workspace events after the
//! mutual-endpoint workspace check. That split prevents an adversary from
//! wrapping arbitrary local event bytes and having them projected as if they
//! came from a trusted connection.

use crate::core::crypto;
use crate::core::network_queues::InboundNetworkRow;
use crate::core::store::Store;
use crate::protocol::event_modules::connection::connection_response;
use crate::protocol::event_modules::connection::types::ConnectionId;
use crate::protocol::event_modules::identity::endpoint::types::{EndpointId, EndpointKeypair};
use crate::protocol::event_modules::identity::{endpoint, invite};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::worker::ProjectionOutput;
use crate::protocol::wire::Writer;
use crate::workers::schema::{self as worker_schema, TransitProvenance, TransitUnwrap};

use super::codec::{self, TransitEnvelopeRef};
use super::types::{BOOTSTRAP_PURPOSE, INVITE_BOOTSTRAP_PURPOSE};

const TRAFFIC_KEY_PURPOSE: &[u8] = b"topo-connection-traffic-key-v1";
const INITIATOR_TO_RESPONDER: &[u8] = b"initiator->responder";
const RESPONDER_TO_INITIATOR: &[u8] = b"responder->initiator";

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnwrappedTransit {
    inners: Vec<Vec<u8>>,
    unwrapped_with: TransitUnwrap,
    sender_endpoint: EndpointId,
}

/// Project one queued network frame into canonical admission rows.
///
/// `remember_route` is false for daemon accepts because their source ports are
/// usually ephemeral. Tests and future stable-route receive paths can set it
/// when the observed source address is meaningful connection metadata.
pub fn project_network_in(
    store: &Store,
    inbound: &InboundNetworkRow,
    remember_route: bool,
) -> Result<ProjectionOutput, String> {
    let local = local_endpoint(store)?;
    let origin = inbound.source.addr();
    let transit = unwrap(store, local, &inbound.bytes)?;
    let mut rows = Vec::with_capacity(transit.inners.len());
    for inner in transit.inners {
        let provenance = TransitProvenance {
            origin,
            local_endpoint: local.endpoint,
            sender_endpoint: transit.sender_endpoint,
            remember_route,
            unwrapped_with: transit.unwrapped_with,
        };
        rows.push(worker_schema::transit_canonical_in_row(inner, provenance));
    }
    Ok(ProjectionOutput::rows(rows))
}

/// Load the endpoint secret material needed to decrypt inbound transit.
///
/// Endpoint events/projectors own this fact. Transit projection only reads it as
/// explicit context for the cryptographic boundary.
fn local_endpoint(store: &Store) -> Result<endpoint::types::EndpointKeypair, String> {
    endpoint::commands::local_keypair(store)?.ok_or_else(|| "local endpoint is missing".to_string())
}

fn unwrap(store: &Store, local: EndpointKeypair, bytes: &[u8]) -> Result<UnwrappedTransit, String> {
    match codec::decode_ref(bytes)? {
        TransitEnvelopeRef::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err("bootstrap transit addressed to a different endpoint".to_string());
            }
            let inner = crypto::x25519_xchacha20poly1305_decrypt(
                &local.secret,
                &sender_endpoint,
                BOOTSTRAP_PURPOSE,
                &codec::associated_data_bootstrap(&sender_endpoint, &recipient_endpoint, &nonce),
                &nonce,
                ciphertext,
            )?;
            Ok(UnwrappedTransit {
                inners: vec![inner],
                unwrapped_with: TransitUnwrap::Bootstrap,
                sender_endpoint,
            })
        }
        TransitEnvelopeRef::InviteBootstrap {
            sender_endpoint,
            recipient_endpoint,
            bootstrap_hash,
            workspace_id,
            invite_event_id,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err(
                    "invite bootstrap transit addressed to a different endpoint".to_string()
                );
            }
            let invite_secret = invite::schema::invite_secret_by_hash(store, &bootstrap_hash)?;
            if invite_secret.workspace_id != Some(workspace_id)
                || invite_secret.invite_event_id != Some(invite_event_id)
            {
                return Err("invite bootstrap key is not scoped to envelope invite".to_string());
            }
            let associated_data = codec::associated_data_invite_bootstrap(
                &sender_endpoint,
                &recipient_endpoint,
                &bootstrap_hash,
                &workspace_id,
                &invite_event_id,
                &nonce,
            );
            let key = crypto::hkdf_sha256_key(
                &invite_secret.bootstrap_secret,
                INVITE_BOOTSTRAP_PURPOSE,
                &associated_data,
            )?;
            let plaintext =
                crypto::xchacha20poly1305_decrypt(&key, &associated_data, &nonce, ciphertext)?;
            Ok(UnwrappedTransit {
                inners: codec::decode_inner_events(&plaintext)?,
                unwrapped_with: TransitUnwrap::InviteBootstrap {
                    bootstrap_hash,
                    workspace_id,
                    invite_event_id,
                },
                sender_endpoint,
            })
        }
        TransitEnvelopeRef::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err("connection transit addressed to a different endpoint".to_string());
            }
            let connection = connection_event(store, connection_id)?;
            let key = derive_directional_key(
                &connection,
                connection_id,
                sender_endpoint,
                recipient_endpoint,
            )?;
            let associated_data = codec::associated_data_connection(
                &connection_id,
                &sender_endpoint,
                &recipient_endpoint,
                &nonce,
            );
            let plaintext =
                crypto::xchacha20poly1305_decrypt(&key, &associated_data, &nonce, ciphertext)?;
            Ok(UnwrappedTransit {
                inners: codec::decode_inner_events(&plaintext)?,
                unwrapped_with: TransitUnwrap::Connection { connection_id },
                sender_endpoint,
            })
        }
    }
}

fn connection_event(
    store: &Store,
    connection_id: ConnectionId,
) -> Result<connection_response::types::ResponseEvent, String> {
    let bytes = event_schema::applied_event_bytes(store, &connection_id)
        .map_err(|err| format!("load connection event: {err}"))?
        .ok_or_else(|| "unknown connection".to_string())?;
    connection_response::codec::decode(&bytes)
        .map_err(|_| "connection id does not name a connection event".to_string())
}

fn derive_directional_key(
    event: &connection_response::types::ResponseEvent,
    connection_id: ConnectionId,
    sender_endpoint: EndpointId,
    recipient_endpoint: EndpointId,
) -> Result<crypto::XChaCha20Poly1305Key, String> {
    let direction = if sender_endpoint == event.to_endpoint
        && recipient_endpoint == event.from_endpoint
    {
        INITIATOR_TO_RESPONDER
    } else if sender_endpoint == event.from_endpoint && recipient_endpoint == event.to_endpoint {
        RESPONDER_TO_INITIATOR
    } else {
        return Err("connection transit direction does not match connection".to_string());
    };

    let mut info = Writer::with_capacity(32 * 4 + direction.len());
    info.id(&connection_id);
    info.id(&event.request_id);
    info.id(&event.to_endpoint);
    info.id(&event.from_endpoint);
    info.raw(direction);
    crypto::hkdf_sha256_key(&event.traffic_secret, TRAFFIC_KEY_PURPOSE, &info.finish())
}

#[cfg(test)]
mod tests {
    use crate::core::network_queues::{InboundNetworkRow, NetworkSource};
    use crate::protocol::event_modules::connection::{connection_response, transit};
    use crate::protocol::event_modules::identity::{endpoint, invite};
    use crate::protocol::event_modules::schema as event_schema;
    use crate::protocol::event_modules::types::EventStatus;
    use crate::protocol::Protocol;
    use crate::workers::schema::{self as worker_schema, TransitUnwrap};

    use super::*;

    fn keypair() -> endpoint::types::EndpointKeypair {
        endpoint::commands::create_local_keypair().value
    }

    #[test]
    fn bootstrap_frame_projects_inner_bytes_with_provenance() {
        let local = keypair();
        let remote = keypair();
        let store = Protocol::open_memory_store().expect("open store");
        store
            .insert_table_rows(endpoint::projector::local_endpoint(local))
            .expect("insert local endpoint");
        let inner = b"inner canonical bytes".to_vec();
        let frame = transit::commands::create_bootstrap(&remote, local.endpoint, &inner)
            .expect("create bootstrap frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("addr")),
            frame,
        );

        let output = project_network_in(&store, &inbound, true).expect("project frame");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, worker_schema::CANONICAL_IN);
        store
            .insert_table_rows(output.rows)
            .expect("insert canonical rows");
        let queued = worker_schema::claim_canonical_in(&store, 1).expect("claim canonical");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].canonical_bytes, inner);
        let provenance = queued[0].provenance.expect("provenance");
        assert_eq!(provenance.local_endpoint, local.endpoint);
        assert_eq!(provenance.sender_endpoint, remote.endpoint);
        assert_eq!(provenance.unwrapped_with, TransitUnwrap::Bootstrap);
        assert!(provenance.remember_route);
    }

    #[test]
    fn rejects_frame_for_another_local_endpoint() {
        let local = keypair();
        let other_local = keypair();
        let remote = keypair();
        let store = Protocol::open_memory_store().expect("open store");
        store
            .insert_table_rows(endpoint::projector::local_endpoint(local))
            .expect("insert local endpoint");
        let frame = transit::commands::create_bootstrap(
            &remote,
            other_local.endpoint,
            b"inner canonical bytes",
        )
        .expect("create bootstrap frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("addr")),
            frame,
        );

        let err = project_network_in(&store, &inbound, false).expect_err("wrong endpoint");

        assert!(err.contains("addressed to a different endpoint"), "{err}");
    }

    #[test]
    fn connection_frame_decrypts_from_connection_event_secret() {
        let local = keypair();
        let remote = keypair();
        let connection = connection_response::types::ResponseEvent {
            from_endpoint: local.endpoint,
            to_endpoint: remote.endpoint,
            request_id: [3; 32],
            traffic_secret: [4; 32],
        };
        let connection_bytes = connection_response::codec::encode(&connection);
        let connection_id = crate::protocol::event_modules::types::event_id(&connection_bytes);
        let connection_record =
            connection_response::codec::record_from_bytes(connection_bytes.clone())
                .expect("connection record");
        let store = Protocol::open_memory_store().expect("open store");
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.push(
            event_schema::event_row(&connection_id, &connection_record, EventStatus::Applied)
                .expect("connection event row"),
        );
        store.insert_table_rows(rows).expect("insert local rows");
        let inner = b"connection inner bytes".to_vec();
        let frame = transit::commands::create_connection_batch(
            remote.endpoint,
            &connection,
            connection_id,
            vec![inner.clone()],
        )
        .expect("create connection frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("addr")),
            frame,
        );

        let output = project_network_in(&store, &inbound, false).expect("project frame");

        assert_eq!(output.rows.len(), 1);
        store
            .insert_table_rows(output.rows)
            .expect("insert canonical rows");
        let queued = worker_schema::claim_canonical_in(&store, 1).expect("claim canonical");
        assert_eq!(queued[0].canonical_bytes, inner);
        let provenance = queued[0].provenance.expect("provenance");
        assert_eq!(
            provenance.unwrapped_with,
            TransitUnwrap::Connection { connection_id }
        );
    }

    #[test]
    fn invite_bootstrap_frame_projects_batched_inner_bytes_with_invite_provenance() {
        // Invariant: invite bootstrap decrypts with the invite-secret row and
        // preserves workspace/invite provenance on every recovered event.
        let local = keypair();
        let remote = keypair();
        let bootstrap_secret = [7; 32];
        let bootstrap_hash = invite::types::bootstrap_secret_hash(&bootstrap_secret);
        let workspace_id = [8; 32];
        let invite_event_id = [9; 32];
        let store = Protocol::open_memory_store().expect("open store");
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.extend(invite::projector::invite_secret(
            bootstrap_hash,
            bootstrap_secret,
            Some(workspace_id),
            Some(invite_event_id),
        ));
        store.insert_table_rows(rows).expect("insert local rows");
        let first = b"first identity bytes".to_vec();
        let second = b"second identity bytes".to_vec();
        let frame = transit::commands::create_invite_bootstrap_batch(
            &remote,
            local.endpoint,
            &bootstrap_secret,
            workspace_id,
            invite_event_id,
            vec![first.clone(), second.clone()],
        )
        .expect("create invite bootstrap frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("addr")),
            frame,
        );

        let output = project_network_in(&store, &inbound, false).expect("project frame");

        assert_eq!(output.rows.len(), 2);
        store
            .insert_table_rows(output.rows)
            .expect("insert canonical rows");
        let mut queued = worker_schema::claim_canonical_in(&store, 2).expect("claim canonical");
        queued.sort_by(|left, right| left.canonical_bytes.cmp(&right.canonical_bytes));
        assert_eq!(queued[0].canonical_bytes, first);
        assert_eq!(queued[1].canonical_bytes, second);
        for row in queued {
            let provenance = row.provenance.expect("provenance");
            assert_eq!(provenance.local_endpoint, local.endpoint);
            assert_eq!(provenance.sender_endpoint, remote.endpoint);
            assert_eq!(
                provenance.unwrapped_with,
                TransitUnwrap::InviteBootstrap {
                    bootstrap_hash,
                    workspace_id,
                    invite_event_id,
                }
            );
        }
    }
}
