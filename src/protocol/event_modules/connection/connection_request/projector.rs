//! Projector for connection request events.
//!
//! This projector is the authority boundary for request facts. It has two
//! valid contexts:
//!
//! ```text
//! local request, no receive metadata
//!   -> store request bytes
//!   -> project local connection(request_id, request.to_endpoint)
//!
//! received bootstrap request, with receive metadata
//!   -> verify receive endpoint/sender/authorization
//!   -> verify invite-secret dependency authorizes bootstrap hash
//!   -> store request bytes
//!   -> project local connection(request_id, receive.local_endpoint)
//!   -> optionally remember the observed route
//! ```
//!
//! The distinction is important. A local request is this node's own intent to
//! connect to the invite endpoint, so it can project a local connection row
//! after admission has applied its declared invite-secret dependency. A received
//! request is untrusted network input until the receive context proves which
//! endpoint unwrapped it and the dependency context proves that the request
//! knows a locally stored invite secret.
//!
//! This projector does not create response events, send bytes, query storage,
//! or reconstruct invite dependencies. Transit supplies local receive context;
//! the codec supplies canonical dependency ids; the common worker supplies only
//! dependencies that already reached `Applied`.

use super::super::schema as projection;
use super::super::types;
use super::codec;
use crate::protocol::event_modules::identity::invite;
use crate::protocol::event_modules::types::ReceiveAuthorization;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn project(envelope: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = envelope.record.canonical_bytes.clone();
    let receive = envelope.context.receive;
    let event = codec::decode(&bytes)?;
    let request_id = types::event_id(&bytes);
    // Always cache the canonical request bytes. Later connection response facts
    // use the request as dependency context to prove they answer this exact
    // request, not merely the same endpoints.
    let mut rows = vec![projection::connection_event_row(request_id, bytes)];
    if let Some(receive) = receive {
        // Network receive context is subjective and therefore must match the
        // canonical request fields before it can become local connection state.
        if event.to_endpoint != receive.local_endpoint() {
            return Err("connection request addressed to a different endpoint".to_string());
        }
        if event.from_endpoint != receive.remote_endpoint() {
            return Err("connection request sender does not match receive sender".to_string());
        }
        if receive.authorization() != ReceiveAuthorization::BootstrapInvite {
            return Err("connection request requires bootstrap invite authorization".to_string());
        }
        // The invite-secret event is deliberately a normal dependency. This is
        // the same fact-graph rule used elsewhere: projectors read declared
        // dependencies from context instead of doing side lookups.
        let invite_secret = envelope
            .context
            .dependency(&event.invite_secret_event_id)
            .ok_or_else(|| "connection request missing invite secret dependency".to_string())?;
        let invite_secret = invite::codec::decode(&invite_secret.canonical_bytes)
            .map_err(|_| "connection request dependency is not an invite secret".to_string())?;
        if invite_secret.bootstrap_hash != event.bootstrap_hash {
            return Err("connection request bootstrap hash is not authorized".to_string());
        }
        // Both peers derive the connection id from the request id and accepting
        // endpoint. On receive, the accepting endpoint is this local endpoint.
        let connection_id = types::connection_id(&request_id, &receive.local_endpoint());
        rows.push(projection::connection_row(
            connection_id,
            event.from_endpoint,
        ));
        if receive.remember_route() {
            // Route learning is local metadata, not a shared event. The worker
            // only sets this flag when the observed origin is stable enough to
            // be used for later sends.
            rows.push(projection::transport_target_row(
                connection_id,
                receive.origin(),
            ));
        }
    } else {
        // Local requests have no receive metadata because this node created
        // them. Admission has already applied the invite-secret dependency, so
        // projection can learn the local view of the connection to the invite
        // endpoint without another network round trip. Scoped identity
        // bootstrap is not authorized here; invite-key transit carries that
        // workspace proof per event.
        let connection_id = types::connection_id(&request_id, &event.to_endpoint);
        rows.push(projection::connection_row(connection_id, event.to_endpoint));
        let invite_secret = envelope
            .context
            .dependency(&event.invite_secret_event_id)
            .ok_or_else(|| "connection request missing invite secret dependency".to_string())?;
        let invite_secret = invite::codec::decode(&invite_secret.canonical_bytes)
            .map_err(|_| "connection request dependency is not an invite secret".to_string())?;
        if invite_secret.bootstrap_hash != event.bootstrap_hash {
            return Err("connection request bootstrap hash is not authorized".to_string());
        }
    }

    Ok(ProjectionOutput::rows(rows))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::protocol::event_modules::connection::connection_request::types::RequestEvent;
    use crate::protocol::event_modules::connection::{schema, types};
    use crate::protocol::event_modules::types::ReceiveMetadata;
    use crate::protocol::event_modules::worker::{DependencyContext, EventContext};

    use super::codec;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn request_record() -> Record {
        codec::record_from_bytes(codec::encode(&RequestEvent {
            from_endpoint: [1; 32],
            to_endpoint: [9; 32],
            nonce: [2; 32],
            bootstrap_hash: [3; 32],
            invite_secret_event_id: [4; 32],
            from_listen_addr: None,
        }))
        .expect("request record")
    }

    fn context_with_dependency<'a>(
        record: &'a Record,
        invite_secret_event_id: [u8; 32],
        invite_record: Record,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: types::event_id(&record.canonical_bytes),
                dependencies: vec![DependencyContext {
                    event_id: invite_secret_event_id,
                    record: invite_record,
                }],
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    fn authorized_request_record() -> (Record, [u8; 32], Record) {
        authorized_request_record_for(invite::types::InviteSecretEvent::new([7; 32]))
    }

    fn scoped_authorized_request_record() -> (Record, [u8; 32], Record) {
        authorized_request_record_for(invite::types::InviteSecretEvent::scoped(
            [7; 32], [6; 32], [5; 32],
        ))
    }

    fn authorized_request_record_for(
        invite_secret: invite::types::InviteSecretEvent,
    ) -> (Record, [u8; 32], Record) {
        let invite_record = invite::codec::record_from_bytes(invite::codec::encode(&invite_secret))
            .expect("invite record");
        let invite_secret_event_id = types::event_id(&invite_record.canonical_bytes);
        let record = codec::record_from_bytes(codec::encode(&RequestEvent {
            from_endpoint: [1; 32],
            to_endpoint: [9; 32],
            nonce: [2; 32],
            bootstrap_hash: invite_secret.bootstrap_hash,
            invite_secret_event_id,
            from_listen_addr: None,
        }))
        .expect("request record");
        (record, invite_secret_event_id, invite_record)
    }

    #[test]
    fn projects_request_bytes_without_receive_metadata() {
        let (record, invite_secret_event_id, invite_record) = authorized_request_record();
        let output = project(&context_with_dependency(
            &record,
            invite_secret_event_id,
            invite_record,
        ))
        .expect("project request");

        assert_eq!(output.rows.len(), 2);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[0].key, types::event_id(&record.canonical_bytes));
        assert_eq!(output.rows[0].value, record.canonical_bytes);
        assert_eq!(output.rows[1].table, schema::CONNECTIONS);
        assert_eq!(
            output.rows[1].key,
            types::connection_id(&types::event_id(&record.canonical_bytes), &[9; 32])
        );
        assert_eq!(output.rows[1].value, [9; 32]);
    }

    #[test]
    fn local_scoped_request_projects_connection_only_not_bootstrap_authorization() {
        let (record, invite_secret_event_id, invite_record) = scoped_authorized_request_record();
        let output = project(&context_with_dependency(
            &record,
            invite_secret_event_id,
            invite_record,
        ))
        .expect("project local scoped request");

        assert_eq!(output.rows.len(), 2);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[1].table, schema::CONNECTIONS);
    }

    #[test]
    fn projects_received_request_connection_and_route_rows() {
        let (record, invite_secret_event_id, invite_record) = authorized_request_record();
        let origin = "127.0.0.1:9000".parse::<SocketAddr>().expect("addr");
        let output = project(&EventWithContext {
            record: &record,
            context: EventContext {
                event_id: types::event_id(&record.canonical_bytes),
                dependencies: vec![DependencyContext {
                    event_id: invite_secret_event_id,
                    record: invite_record,
                }],
                labels: Vec::new(),
                receive: Some(ReceiveMetadata::bootstrap_invite(
                    origin, [9; 32], [1; 32], true,
                )),
            },
        })
        .expect("project received request");

        assert_eq!(output.rows.len(), 3);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[1].table, schema::CONNECTIONS);
        assert_eq!(output.rows[2].table, schema::TRANSPORT_TARGETS);
        assert_eq!(
            output.rows[1].key,
            types::connection_id(&types::event_id(&record.canonical_bytes), &[9; 32])
        );
        assert_eq!(output.rows[1].value, [1; 32]);
        assert_eq!(output.rows[2].value, origin.to_string().into_bytes());
    }

    #[test]
    fn rejects_received_request_without_bootstrap_authorization() {
        let record = request_record();

        assert_eq!(
            project(&EventWithContext {
                record: &record,
                context: EventContext {
                    event_id: types::event_id(&record.canonical_bytes),
                    dependencies: Vec::new(),
                    labels: Vec::new(),
                    receive: Some(ReceiveMetadata::endpoint_receive(
                        "127.0.0.1:9000".parse::<SocketAddr>().expect("addr"),
                        [9; 32],
                        [1; 32],
                        true,
                    )),
                },
            })
            .expect_err("unauthorized receive must fail"),
            "connection request requires bootstrap invite authorization"
        );
    }

    #[test]
    fn rejects_received_request_when_invite_secret_dependency_is_missing() {
        let (record, _, _) = authorized_request_record();

        assert_eq!(
            project(&EventWithContext {
                record: &record,
                context: EventContext {
                    event_id: types::event_id(&record.canonical_bytes),
                    dependencies: Vec::new(),
                    labels: Vec::new(),
                    receive: Some(ReceiveMetadata::bootstrap_invite(
                        "127.0.0.1:9000".parse::<SocketAddr>().expect("addr"),
                        [9; 32],
                        [1; 32],
                        true,
                    )),
                },
            })
            .expect_err("missing invite dependency must fail"),
            "connection request missing invite secret dependency"
        );
    }

    #[test]
    fn rejects_received_request_when_invite_secret_hash_does_not_match() {
        let (record, invite_secret_event_id, _) = authorized_request_record();
        let wrong_invite = invite::types::InviteSecretEvent::new([8; 32]);
        let wrong_invite_record =
            invite::codec::record_from_bytes(invite::codec::encode(&wrong_invite))
                .expect("wrong invite record");

        assert_eq!(
            project(&EventWithContext {
                record: &record,
                context: EventContext {
                    event_id: types::event_id(&record.canonical_bytes),
                    dependencies: vec![DependencyContext {
                        event_id: invite_secret_event_id,
                        record: wrong_invite_record,
                    }],
                    labels: Vec::new(),
                    receive: Some(ReceiveMetadata::bootstrap_invite(
                        "127.0.0.1:9000".parse::<SocketAddr>().expect("addr"),
                        [9; 32],
                        [1; 32],
                        true,
                    )),
                },
            })
            .expect_err("wrong invite dependency must fail"),
            "connection request bootstrap hash is not authorized"
        );
    }
}
