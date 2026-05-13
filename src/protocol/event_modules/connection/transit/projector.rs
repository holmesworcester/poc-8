//! Projector for inbound transit frames.
//!
//! Transit frames are connection-scoped transport events. They are not shared
//! canonical history and are usually not stored as event records; the worker
//! projects them directly from one queued core network row. The projector
//! authenticates and decrypts the envelope, then emits `canonical.in` rows
//! carrying the recovered inner bytes and the transit event type that proved
//! how those bytes arrived.
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
//! endpoint bootstrap may only admit connection requests; handshake responses
//! may only admit connection responses; connection transit may admit
//! connection-scoped sync events or shared workspace events after the
//! workspace-authorization check. That split prevents an adversary from
//! wrapping arbitrary local event bytes and having them projected as if they
//! came from a trusted connection.

use crate::core::crypto;
use crate::core::network_queues::InboundNetworkRow;
use crate::core::store::Store;
use crate::protocol::event_modules::connection::{
    connection_ephemeral_secret, connection_request, connection_response, types::ConnectionId,
};
use crate::protocol::event_modules::identity::endpoint::types::{EndpointId, EndpointKeypair};
use crate::protocol::event_modules::identity::{self, endpoint, invite};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::sync;
use crate::protocol::event_modules::types::{EventId, ReceiveMetadata};
use crate::protocol::event_modules::worker::{ProjectionOutput, ReceivedRecord};
use crate::workers::schema as worker_schema;
use std::net::SocketAddr;

use super::super::schema as connection_schema;
use super::codec::{self, TransitEnvelopeRef};
use super::types::{BOOTSTRAP_PURPOSE, CONNECTION_PURPOSE};

/// Provenance established by projecting one inbound transit transport event.
///
/// This is queue metadata for the recovered inner canonical bytes, not shared
/// canonical history. Simulation or tracing may store outer transit bytes as a
/// connection-scoped event, but the normal daemon projects them directly into
/// `canonical.in`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitProvenance {
    /// Socket address that delivered the outer frame.
    origin: SocketAddr,
    /// Local endpoint key used to unwrap the frame.
    local_endpoint: EndpointId,
    /// Remote endpoint proven by the outer frame.
    sender_endpoint: EndpointId,
    /// Whether projection may remember `origin` as a usable route.
    remember_route: bool,
    /// Which connection-scoped transit event type produced the inner bytes.
    event_type: TransitEventType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitEventType {
    /// Bootstrap envelope addressed directly to the local endpoint key.
    Bootstrap,
    /// Response to a native connection handshake request.
    ConnectionHandshake { request_id: EventId },
    /// Established connection envelope addressed through a connection id.
    Connection { connection_id: ConnectionId },
}

impl TransitProvenance {
    pub fn bootstrap(
        origin: SocketAddr,
        local_endpoint: EndpointId,
        sender_endpoint: EndpointId,
        remember_route: bool,
    ) -> Self {
        Self::new(
            origin,
            local_endpoint,
            sender_endpoint,
            remember_route,
            TransitEventType::Bootstrap,
        )
    }

    pub fn connection_handshake(
        origin: SocketAddr,
        local_endpoint: EndpointId,
        sender_endpoint: EndpointId,
        remember_route: bool,
        request_id: EventId,
    ) -> Self {
        Self::new(
            origin,
            local_endpoint,
            sender_endpoint,
            remember_route,
            TransitEventType::ConnectionHandshake { request_id },
        )
    }

    pub fn connection(
        origin: SocketAddr,
        local_endpoint: EndpointId,
        sender_endpoint: EndpointId,
        remember_route: bool,
        connection_id: ConnectionId,
    ) -> Self {
        Self::new(
            origin,
            local_endpoint,
            sender_endpoint,
            remember_route,
            TransitEventType::Connection { connection_id },
        )
    }

    pub(crate) fn with_event_type(
        origin: SocketAddr,
        local_endpoint: EndpointId,
        sender_endpoint: EndpointId,
        remember_route: bool,
        event_type: TransitEventType,
    ) -> Self {
        Self::new(
            origin,
            local_endpoint,
            sender_endpoint,
            remember_route,
            event_type,
        )
    }

    pub fn origin(self) -> SocketAddr {
        self.origin
    }

    pub fn local_endpoint(self) -> EndpointId {
        self.local_endpoint
    }

    pub fn sender_endpoint(self) -> EndpointId {
        self.sender_endpoint
    }

    pub fn remember_route(self) -> bool {
        self.remember_route
    }

    pub fn event_type(self) -> TransitEventType {
        self.event_type
    }

    fn new(
        origin: SocketAddr,
        local_endpoint: EndpointId,
        sender_endpoint: EndpointId,
        remember_route: bool,
        event_type: TransitEventType,
    ) -> Self {
        Self {
            origin,
            local_endpoint,
            sender_endpoint,
            remember_route,
            event_type,
        }
    }
}

pub(crate) fn record_from_transit_canonical_in(
    store: &Store,
    bytes: Vec<u8>,
    provenance: TransitProvenance,
) -> Result<ReceivedRecord, String> {
    match provenance.event_type() {
        TransitEventType::Bootstrap => {
            if !connection_request::codec::is_request(&bytes) {
                return Err(
                    "endpoint bootstrap transit only carries connection requests".to_string(),
                );
            }
            let record = connection_request::codec::received_record_from_bytes(bytes)?;
            return Ok(ReceivedRecord::with_receive(
                record,
                ReceiveMetadata::bootstrap_invite(
                    provenance.origin(),
                    provenance.local_endpoint(),
                    provenance.sender_endpoint(),
                    provenance.remember_route(),
                ),
            ));
        }
        TransitEventType::ConnectionHandshake { request_id } => {
            if !connection_response::codec::is_response(&bytes) {
                return Err(
                    "connection handshake response only carries connection events".to_string(),
                );
            }
            let record =
                connection_response::codec::received_record_from_bytes(store, bytes, request_id)?;
            return Ok(ReceivedRecord::with_receive(
                record,
                ReceiveMetadata::endpoint_receive(
                    provenance.origin(),
                    provenance.local_endpoint(),
                    provenance.sender_endpoint(),
                    false,
                ),
            ));
        }
        TransitEventType::Connection { connection_id } => {
            if connection_request::codec::is_request(&bytes) {
                return Err("connection transit cannot carry connection requests".to_string());
            }
            if connection_response::codec::is_response(&bytes) {
                let record = connection_response::codec::record_from_bytes(bytes)?;
                return Ok(ReceivedRecord::with_receive(
                    record,
                    ReceiveMetadata::endpoint_receive(
                        provenance.origin(),
                        provenance.local_endpoint(),
                        provenance.sender_endpoint(),
                        provenance.remember_route(),
                    ),
                ));
            }
            if sync::is_connection_scoped_event(&bytes) {
                return sync::inbound_record_from_connection_bytes(connection_id, bytes)
                    .map(ReceivedRecord::new);
            }
        }
    }
    let TransitEventType::Connection { connection_id } = provenance.event_type() else {
        return Err("transit provenance cannot admit this event".to_string());
    };
    let record = crate::protocol::event_modules::event_from_bytes(bytes)?;
    if !record.scope.is_shared() {
        return Err(
            "connection transit only accepts shared or connection-scoped events".to_string(),
        );
    }
    let workspace_id = record
        .workspace_id
        .ok_or_else(|| "transit shared in requires a workspace".to_string())?;
    let mut allowed_workspaces = Vec::new();
    if let Some(workspace_id) = invite_workspace(store, connection_id)? {
        allowed_workspaces.push(workspace_id);
    }
    allowed_workspaces.extend(identity::invite_accepted::schema::accepted_workspace_ids(
        store,
        provenance.local_endpoint(),
    )?);
    allowed_workspaces.extend(identity::endpoint_shared::schema::mutual_workspace_ids(
        store,
        provenance.local_endpoint(),
        provenance.sender_endpoint(),
    )?);
    if !allowed_workspaces
        .iter()
        .any(|allowed| allowed == &workspace_id)
    {
        return Err("transit shared in rejected event outside sender workspace".to_string());
    }
    Ok(ReceivedRecord::new(record))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnwrappedTransit {
    inners: Vec<Vec<u8>>,
    event_type: TransitEventType,
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
    let transit = unwrap(store, local, &inbound.bytes, |connection_id| {
        remote_endpoint(store, *connection_id)
    })?;
    let mut rows = Vec::with_capacity(transit.inners.len());
    for inner in transit.inners {
        let provenance = TransitProvenance::with_event_type(
            origin,
            local.endpoint,
            transit.sender_endpoint,
            remember_route,
            transit.event_type,
        );
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
    store: &Store,
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
                event_type: TransitEventType::Bootstrap,
                sender_endpoint,
            })
        }
        TransitEnvelopeRef::ConnectionHandshakeResponse {
            request_id,
            sender_endpoint,
            recipient_endpoint,
            responder_ephemeral_public_key,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err(
                    "connection handshake response addressed to a different endpoint".to_string(),
                );
            }
            let associated_data = codec::associated_data_connection_handshake_response(
                &request_id,
                &sender_endpoint,
                &recipient_endpoint,
                &responder_ephemeral_public_key,
                &nonce,
            );
            let Some((request, invite_secret, initiator_ephemeral)) =
                handshake_response_dependencies(store, request_id)?
            else {
                return Ok(UnwrappedTransit {
                    inners: Vec::new(),
                    event_type: TransitEventType::ConnectionHandshake { request_id },
                    sender_endpoint,
                });
            };
            let inner = match connection_response::commands::decrypt_handshake_response(
                connection_response::commands::DecryptHandshakeResponse {
                    request_id,
                    request: &request,
                    invite_secret: &invite_secret,
                    initiator_ephemeral: &initiator_ephemeral,
                    responder_ephemeral_public_key,
                    associated_data: &associated_data,
                    nonce: &nonce,
                    ciphertext,
                },
            ) {
                Ok(inner) => inner,
                Err(err) => return Err(err),
            };
            Ok(UnwrappedTransit {
                inners: vec![inner],
                event_type: TransitEventType::ConnectionHandshake { request_id },
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
            let connection_event = connection_event(store, connection_id)?;
            let connection =
                connection_response::codec::decode(&connection_event).map_err(|_| {
                    "connection transit dependency is not a connection event".to_string()
                })?;
            let associated_data = codec::associated_data_connection(
                &connection_id,
                &sender_endpoint,
                &recipient_endpoint,
                &nonce,
            );
            let key = crypto::hkdf_sha256_key(
                &connection.connection_secret,
                CONNECTION_PURPOSE,
                &associated_data,
            )?;
            let plaintext =
                crypto::xchacha20poly1305_decrypt(&key, &associated_data, &nonce, ciphertext)?;
            Ok(UnwrappedTransit {
                inners: codec::decode_inner_events(&plaintext)?,
                event_type: TransitEventType::Connection { connection_id },
                sender_endpoint,
            })
        }
    }
}

fn handshake_response_dependencies(
    store: &Store,
    request_id: EventId,
) -> Result<
    Option<(
        connection_request::types::RequestEvent,
        invite::types::InviteSecretEvent,
        connection_ephemeral_secret::types::EphemeralSecretEvent,
    )>,
    String,
> {
    let Some(request_bytes) = event_schema::event_bytes(store, &request_id)
        .map_err(|err| format!("load connection request event: {err}"))?
        .or_else(|| connection_event(store, request_id).ok())
    else {
        return Ok(None);
    };
    let request = connection_request::codec::decode(&request_bytes)?;
    let invite_secret_bytes = event_schema::event_bytes(store, &request.invite_secret_event_id)
        .map_err(|err| format!("load invite secret event: {err}"))?
        .ok_or_else(|| "missing invite secret event".to_string())?;
    let invite_secret = invite::codec::decode(&invite_secret_bytes)
        .map_err(|_| "connection dependency is not an invite secret".to_string())?;
    let initiator_bytes =
        event_schema::event_bytes(store, &request.initiator_ephemeral_secret_event_id)
            .map_err(|err| format!("load connection ephemeral event: {err}"))?
            .ok_or_else(|| "missing connection ephemeral event".to_string())?;
    let initiator_ephemeral = connection_ephemeral_secret::codec::decode(&initiator_bytes)
        .map_err(|_| "connection dependency is not an ephemeral secret".to_string())?;
    Ok(Some((request, invite_secret, initiator_ephemeral)))
}

fn connection_event(store: &Store, connection_id: ConnectionId) -> Result<Vec<u8>, String> {
    store
        .table_row(connection_schema::CONNECTION_EVENTS, &connection_id)
        .map_err(|err| format!("load connection event: {err}"))?
        .ok_or_else(|| "unknown connection event".to_string())
}

fn remote_endpoint(store: &Store, connection_id: ConnectionId) -> Result<EndpointId, String> {
    let bytes = store
        .table_row(connection_schema::CONNECTIONS, &connection_id)
        .map_err(|err| format!("load connection: {err}"))?
        .ok_or_else(|| "unknown connection".to_string())?;
    endpoint_id_from_bytes(&bytes)
}

fn invite_workspace(store: &Store, connection_id: ConnectionId) -> Result<Option<EventId>, String> {
    let Some(bytes) = store
        .table_row(
            connection_schema::CONNECTION_INVITE_WORKSPACES,
            &connection_id,
        )
        .map_err(|err| format!("load connection invite workspace: {err}"))?
    else {
        return Ok(None);
    };
    id_from_bytes(&bytes).map(Some)
}

fn endpoint_id_from_bytes(bytes: &[u8]) -> Result<EndpointId, String> {
    id_from_bytes(bytes).map_err(|_| "stored endpoint id is malformed".to_string())
}

fn id_from_bytes(bytes: &[u8]) -> Result<EventId, String> {
    if bytes.len() != 32 {
        return Err("stored id is malformed".to_string());
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::core::network_queues::{InboundNetworkRow, NetworkSource};
    use crate::protocol::event_modules::connection::transit;
    use crate::protocol::event_modules::identity::endpoint;
    use crate::protocol::Protocol;
    use crate::workers::schema as worker_schema;

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
        assert_eq!(provenance.local_endpoint(), local.endpoint);
        assert_eq!(provenance.sender_endpoint(), remote.endpoint);
        assert_eq!(provenance.event_type(), TransitEventType::Bootstrap);
        assert!(provenance.remember_route());
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
