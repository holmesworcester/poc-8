//! Projector for connection response events.
//!
//! Responses are connection facts, not transport effects. They answer a
//! specific request and their event id is the established connection id.
//!
//! This projector has two legal modes:
//!
//! ```text
//! local response, no receive metadata
//!   -> verify request dependency
//!   -> verify responder ephemeral dependency
//!   -> store connection bytes
//!   -> project connection(response_event_id, response.to_endpoint)
//!
//! received response, with endpoint receive metadata
//!   -> verify request dependency
//!   -> verify initiator ephemeral dependency and derived connection secret
//!   -> verify receive endpoint/sender/authorization
//!   -> store connection bytes
//!   -> project connection(response_event_id, response.from_endpoint)
//!   -> optionally remember the observed route
//! ```
//!
//! This separation mirrors the request projector. Canonical bytes declare the
//! dependency and derived id. Receive metadata supplies only local provenance:
//! which endpoint received the fact from which remote endpoint and route. The
//! projector combines those two sources of context before writing any local
//! connection or route rows.
//!
//! This file intentionally does not send bytes, answer requests, poll TCP, or
//! repair missing request state. Missing dependencies remain event-pipeline
//! work; route writes happen only when receive metadata explicitly permits them.

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::super::connection_ephemeral_secret;
use super::super::connection_request;
use super::super::schema as projection;
use super::codec;
use super::commands;
use crate::protocol::event_modules::types::ReceiveAuthorization;

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = event.record.canonical_bytes.clone();
    let receive = event.context.receive;
    let response = codec::decode(&bytes)?;
    let connection_id = event.context.event_id;
    // Request bytes are dependency context supplied by the common worker. If
    // the request is absent or failed projection, this response cannot project.
    let request = event
        .context
        .dependency(&response.request_id)
        .ok_or_else(|| "connection response missing request dependency".to_string())?;
    let request = connection_request::codec::decode(&request.canonical_bytes)
        .map_err(|_| "connection response references a non-request event".to_string())?;
    if request.from_endpoint != response.to_endpoint {
        return Err("connection response references another endpoint's request".to_string());
    }
    if request.to_endpoint != response.from_endpoint {
        return Err("connection response sender does not match request recipient".to_string());
    }
    if response.invite_secret_event_id != request.invite_secret_event_id {
        return Err("connection response invite dependency does not match request".to_string());
    }
    if response.initiator_ephemeral_secret_event_id != request.initiator_ephemeral_secret_event_id {
        return Err("connection response initiator ephemeral does not match request".to_string());
    }
    if response.handshake_hash
        != commands::public_handshake_hash(
            response.request_id,
            &request,
            &response.responder_ephemeral_public_key,
        )
    {
        return Err("connection response handshake hash does not match transcript".to_string());
    }
    let invite_secret = event
        .context
        .dependency(&response.invite_secret_event_id)
        .ok_or_else(|| "connection response missing invite secret dependency".to_string())?;
    let invite_secret = crate::protocol::event_modules::identity::invite::codec::decode(
        &invite_secret.canonical_bytes,
    )
    .map_err(|_| "connection response dependency is not an invite secret".to_string())?;
    if invite_secret.bootstrap_hash != request.bootstrap_hash {
        return Err("connection response invite secret does not match request".to_string());
    }

    // Always cache the canonical response bytes so future facts can depend on
    // exactly this response event if the protocol starts using that edge.
    let mut rows = vec![projection::connection_event_row(connection_id, bytes)];
    rows.push(projection::request_connection_row(
        response.request_id,
        connection_id,
    ));
    if let Some(receive) = receive {
        // Received responses are useful only when transit provenance agrees
        // with the canonical body. Otherwise a peer could forward a valid
        // response for a different local endpoint or sender.
        if response.to_endpoint != receive.local_endpoint() {
            return Err("connection response addressed to a different endpoint".to_string());
        }
        if response.from_endpoint != receive.remote_endpoint() {
            return Err("connection response sender does not match receive sender".to_string());
        }
        if receive.authorization() != ReceiveAuthorization::EndpointReceive {
            return Err("connection response requires endpoint receive authorization".to_string());
        }
        let initiator = event
            .context
            .dependency(&response.initiator_ephemeral_secret_event_id)
            .ok_or_else(|| {
                "connection response missing initiator ephemeral dependency".to_string()
            })?;
        let initiator = connection_ephemeral_secret::codec::decode(&initiator.canonical_bytes)
            .map_err(|_| "connection response dependency is not an ephemeral secret".to_string())?;
        let material = commands::initiator_material(
            response.request_id,
            &request,
            &invite_secret,
            &initiator,
            &response.responder_ephemeral_public_key,
        )?;
        if response.connection_secret != material.connection_secret {
            return Err("connection response secret does not match handshake".to_string());
        }
        // The route and remote endpoint row are local projections from a
        // response that has passed both dependency validation and receive
        // provenance validation.
        rows.push(projection::connection_row(
            connection_id,
            response.from_endpoint,
        ));
        if let Some(workspace_id) = invite_secret.workspace_id {
            rows.push(projection::connection_invite_workspace_row(
                connection_id,
                workspace_id,
            ));
        }
        if receive.remember_route() {
            // Route learning remains subjective metadata; it is never encoded
            // into the response fact and is only written when the worker marks
            // the observed route as reusable.
            rows.push(projection::transport_target_row(
                connection_id,
                receive.origin(),
            ));
        }
    } else {
        let responder = event
            .context
            .dependency(&response.responder_ephemeral_secret_event_id)
            .ok_or_else(|| {
                "connection response missing responder ephemeral dependency".to_string()
            })?;
        let responder = connection_ephemeral_secret::codec::decode(&responder.canonical_bytes)
            .map_err(|_| "connection response dependency is not an ephemeral secret".to_string())?;
        if responder.owner_endpoint != response.from_endpoint {
            return Err(
                "connection response responder ephemeral owner does not match sender".to_string(),
            );
        }
        if responder.ephemeral_public_key != response.responder_ephemeral_public_key {
            return Err(
                "connection response responder ephemeral public key does not match dependency"
                    .to_string(),
            );
        }
        rows.push(projection::connection_row(
            connection_id,
            response.to_endpoint,
        ));
        if let Some(workspace_id) = invite_secret.workspace_id {
            rows.push(projection::connection_invite_workspace_row(
                connection_id,
                workspace_id,
            ));
        }
        if let Some(addr) = request.from_listen_addr {
            rows.push(projection::transport_target_row(connection_id, addr));
        }
    }
    Ok(ProjectionOutput::rows(rows))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::core::crypto;
    use crate::protocol::event_modules::connection::connection_ephemeral_secret;
    use crate::protocol::event_modules::connection::connection_response::types::ResponseEvent;
    use crate::protocol::event_modules::connection::{connection_request, schema};
    use crate::protocol::event_modules::identity::invite;
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::types::ReceiveMetadata;
    use crate::protocol::event_modules::worker::{DependencyContext, EventContext};

    use super::codec;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    struct Fixture {
        request_id: [u8; 32],
        request_record: Record,
        invite_id: [u8; 32],
        invite_record: Record,
        initiator_ephemeral_id: [u8; 32],
        initiator_ephemeral_record: Record,
        responder_ephemeral_id: [u8; 32],
        responder_ephemeral_record: Record,
        response_record: Record,
        responder_endpoint: [u8; 32],
    }

    fn fixture() -> Fixture {
        let responder_static = [4; 32];
        let responder_endpoint = crypto::x25519_public_key(&responder_static);
        let invite_secret = invite::types::InviteSecretEvent::new([7; 32]);
        let invite_record = invite::codec::record_from_bytes(invite::codec::encode(&invite_secret))
            .expect("invite record");
        let invite_id = event_id(&invite_record.canonical_bytes);
        let initiator_ephemeral = connection_ephemeral_secret::types::EphemeralSecretEvent {
            owner_endpoint: [1; 32],
            ephemeral_private_key: [8; 32],
            ephemeral_public_key: crypto::x25519_public_key(&[8; 32]),
            created_at_ms: 0,
        };
        let initiator_ephemeral_record = connection_ephemeral_secret::codec::record_from_bytes(
            connection_ephemeral_secret::codec::encode(&initiator_ephemeral),
        )
        .expect("initiator ephemeral record");
        let initiator_ephemeral_id = event_id(&initiator_ephemeral_record.canonical_bytes);
        let request = connection_request::commands::sign_with_invite(
            connection_request::types::RequestEvent {
                from_endpoint: [1; 32],
                to_endpoint: responder_endpoint,
                nonce: [2; 32],
                invite_event_id: invite_secret.invite_event_id.unwrap_or([3; 32]),
                bootstrap_hash: invite_secret.bootstrap_hash,
                invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
                invite_secret_event_id: invite_id,
                initiator_ephemeral_secret_event_id: initiator_ephemeral_id,
                initiator_ephemeral_public_key: initiator_ephemeral.ephemeral_public_key,
                from_listen_addr: Some("127.0.0.1:9999".parse().expect("addr")),
            },
            &invite_secret,
        )
        .expect("sign with invite");
        let request_record = connection_request::codec::record_from_bytes(
            connection_request::codec::encode(&request),
        )
        .expect("request record");
        let request_id = event_id(&request_record.canonical_bytes);
        let responder_ephemeral = connection_ephemeral_secret::types::EphemeralSecretEvent {
            owner_endpoint: responder_endpoint,
            ephemeral_private_key: [9; 32],
            ephemeral_public_key: crypto::x25519_public_key(&[9; 32]),
            created_at_ms: 0,
        };
        let responder_ephemeral_record = connection_ephemeral_secret::codec::record_from_bytes(
            connection_ephemeral_secret::codec::encode(&responder_ephemeral),
        )
        .expect("responder ephemeral record");
        let responder_ephemeral_id = event_id(&responder_ephemeral_record.canonical_bytes);
        let material = commands::initiator_material(
            request_id,
            &request,
            &invite_secret,
            &initiator_ephemeral,
            &responder_ephemeral.ephemeral_public_key,
        )
        .expect("material");
        let response = ResponseEvent {
            from_endpoint: responder_endpoint,
            to_endpoint: [1; 32],
            request_id,
            invite_secret_event_id: invite_id,
            initiator_ephemeral_secret_event_id: initiator_ephemeral_id,
            responder_ephemeral_secret_event_id: responder_ephemeral_id,
            responder_ephemeral_public_key: responder_ephemeral.ephemeral_public_key,
            handshake_hash: material.handshake_hash,
            connection_secret: material.connection_secret,
        };
        let response_record =
            codec::record_from_bytes(codec::encode(&response)).expect("response record");
        Fixture {
            request_id,
            request_record,
            invite_id,
            invite_record,
            initiator_ephemeral_id,
            initiator_ephemeral_record,
            responder_ephemeral_id,
            responder_ephemeral_record,
            response_record,
            responder_endpoint,
        }
    }

    #[test]
    fn local_response_projects_connection_from_response_event_id() {
        let fixture = fixture();
        let connection_id = event_id(&fixture.response_record.canonical_bytes);

        let output = project(&EventWithContext {
            record: &fixture.response_record,
            context: EventContext {
                event_id: connection_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: fixture.request_id,
                        record: fixture.request_record,
                    },
                    DependencyContext {
                        event_id: fixture.invite_id,
                        record: fixture.invite_record,
                    },
                    DependencyContext {
                        event_id: fixture.responder_ephemeral_id,
                        record: fixture.responder_ephemeral_record,
                    },
                ],
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        })
        .expect("project response");

        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[0].key, connection_id);
        assert_eq!(output.rows[1].table, schema::REQUEST_CONNECTIONS);
        assert_eq!(output.rows[2].table, schema::CONNECTIONS);
        assert_eq!(output.rows[2].key, connection_id);
        assert_eq!(output.rows[2].value, [1; 32]);
        assert_eq!(output.rows[3].table, schema::TRANSPORT_TARGETS);
    }

    #[test]
    fn received_response_validates_secret_and_projects_route() {
        let fixture = fixture();
        let connection_id = event_id(&fixture.response_record.canonical_bytes);
        let origin = "127.0.0.1:9001".parse::<SocketAddr>().expect("addr");

        let output = project(&EventWithContext {
            record: &fixture.response_record,
            context: EventContext {
                event_id: connection_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: fixture.request_id,
                        record: fixture.request_record,
                    },
                    DependencyContext {
                        event_id: fixture.invite_id,
                        record: fixture.invite_record,
                    },
                    DependencyContext {
                        event_id: fixture.initiator_ephemeral_id,
                        record: fixture.initiator_ephemeral_record,
                    },
                ],
                labels: Vec::new(),
                receive: Some(ReceiveMetadata::endpoint_receive(
                    origin,
                    [1; 32],
                    fixture.responder_endpoint,
                    true,
                )),
                now_unix_minute: None,
            },
        })
        .expect("project response");

        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[2].table, schema::CONNECTIONS);
        assert_eq!(output.rows[2].value, fixture.responder_endpoint);
        assert_eq!(output.rows[3].table, schema::TRANSPORT_TARGETS);
        assert_eq!(output.rows[3].value, origin.to_string().into_bytes());
    }

    #[test]
    fn rejects_received_response_without_endpoint_receive_authorization() {
        let fixture = fixture();

        assert_eq!(
            project(&EventWithContext {
                record: &fixture.response_record,
                context: EventContext {
                    event_id: event_id(&fixture.response_record.canonical_bytes),
                    dependencies: vec![
                        DependencyContext {
                            event_id: fixture.request_id,
                            record: fixture.request_record,
                        },
                        DependencyContext {
                            event_id: fixture.invite_id,
                            record: fixture.invite_record,
                        },
                        DependencyContext {
                            event_id: fixture.initiator_ephemeral_id,
                            record: fixture.initiator_ephemeral_record,
                        },
                    ],
                    labels: Vec::new(),
                    receive: Some(ReceiveMetadata::bootstrap_invite(
                        "127.0.0.1:9001".parse::<SocketAddr>().expect("addr"),
                        [1; 32],
                        fixture.responder_endpoint,
                        true,
                    )),
                    now_unix_minute: None,
                },
            })
            .expect_err("unauthorized response receive must fail"),
            "connection response requires endpoint receive authorization"
        );
    }

    #[test]
    fn rejects_received_response_when_receive_sender_does_not_match_response_sender() {
        let fixture = fixture();

        assert_eq!(
            project(&EventWithContext {
                record: &fixture.response_record,
                context: EventContext {
                    event_id: event_id(&fixture.response_record.canonical_bytes),
                    dependencies: vec![
                        DependencyContext {
                            event_id: fixture.request_id,
                            record: fixture.request_record,
                        },
                        DependencyContext {
                            event_id: fixture.invite_id,
                            record: fixture.invite_record,
                        },
                        DependencyContext {
                            event_id: fixture.initiator_ephemeral_id,
                            record: fixture.initiator_ephemeral_record,
                        },
                    ],
                    labels: Vec::new(),
                    receive: Some(ReceiveMetadata::endpoint_receive(
                        "127.0.0.1:9001".parse::<SocketAddr>().expect("addr"),
                        [1; 32],
                        [99; 32],
                        true,
                    )),
                    now_unix_minute: None,
                },
            })
            .expect_err("wrong receive sender must fail"),
            "connection response sender does not match receive sender"
        );
    }
}
