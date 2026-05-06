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
//!   + local endpoint secret
//!   + optional connection -> expected remote endpoint
//!   -> authenticated inner canonical bytes
//!   -> canonical.in rows with transit provenance
//! ```
//!
//! The next admission step classifies those inner bytes under the provenance:
//! bootstrap transit may only admit connection requests; connection transit may
//! admit connection-scoped sync events or shared workspace events after the
//! mutual-endpoint workspace check. That split prevents an adversary from
//! wrapping arbitrary local event bytes and having them projected as if they
//! came from a trusted connection.

use crate::core::crypto;
use crate::core::network_queues::InboundNetworkRow;
use crate::core::store::Store;
use crate::protocol::event_modules::connection::types::ConnectionId;
use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::identity::endpoint::types::{EndpointId, EndpointKeypair};
use crate::protocol::event_modules::worker::ProjectionOutput;
use crate::workers::schema::{self as worker_schema, TransitProvenance, TransitUnwrap};

use super::super::schema as connection_schema;
use super::codec::{self, TransitEnvelopeRef};
use super::types::{BOOTSTRAP_PURPOSE, CONNECTION_PURPOSE};

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnwrappedTransit {
    inners: Vec<Vec<u8>>,
    connection_id: Option<ConnectionId>,
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
    let transit = unwrap(local, &inbound.bytes, |connection_id| {
        connection_schema::remote_endpoint(store, *connection_id)
    })?;
    let mut rows = Vec::with_capacity(transit.inners.len());
    for inner in transit.inners {
        let provenance = TransitProvenance {
            origin,
            local_endpoint: local.endpoint,
            sender_endpoint: transit.sender_endpoint,
            remember_route,
            unwrapped_with: match transit.connection_id {
                Some(connection_id) => TransitUnwrap::Connection { connection_id },
                None => TransitUnwrap::Bootstrap,
            },
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

fn unwrap(
    local: EndpointKeypair,
    bytes: &[u8],
    remote_endpoint: impl FnOnce(&ConnectionId) -> Result<EndpointId, String>,
) -> Result<UnwrappedTransit, String> {
    // The caller supplies remote endpoint lookup for established connections.
    // That keeps storage access outside the cryptographic transform.
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
                connection_id: None,
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
            let remote = remote_endpoint(&connection_id)?;
            if sender_endpoint != remote {
                return Err("connection transit sender does not match connection".to_string());
            }
            let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
                &local.secret,
                &sender_endpoint,
                CONNECTION_PURPOSE,
                &codec::associated_data_connection(
                    &connection_id,
                    &sender_endpoint,
                    &recipient_endpoint,
                    &nonce,
                ),
                &nonce,
                ciphertext,
            )?;
            Ok(UnwrappedTransit {
                inners: codec::decode_inner_events(&plaintext)?,
                connection_id: Some(connection_id),
                sender_endpoint,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::core::network_queues::{InboundNetworkRow, NetworkSource};
    use crate::protocol::event_modules::connection::transit;
    use crate::protocol::event_modules::identity::endpoint;
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
}
