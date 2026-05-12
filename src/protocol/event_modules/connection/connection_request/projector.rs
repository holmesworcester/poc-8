//! Projector for connection request events.
//!
//! This projector is the authority boundary for request facts. It has two
//! valid contexts:
//!
//! ```text
//! local request, no receive metadata
//!   -> store request bytes
//!   -> verify local ephemeral dependency matches request public key
//!   -> queue retryable connection attempt when the invite dependency has an addr
//!
//! received bootstrap request, with receive metadata
//!   -> verify receive endpoint/sender/authorization
//!   -> verify invite-secret dependency authorizes bootstrap signature
//!   -> store request bytes
//!   -> queue response work when the request advertises a daemon addr
//! ```
//!
//! The distinction is important. A local request is this node's own intent to
//! connect to the invite endpoint, but it is not a connection until a response
//! event arrives and projects. A received request is untrusted network input
//! until the receive context proves which endpoint unwrapped it and the
//! dependency context proves that the request knows a locally stored invite
//! secret.
//!
//! This projector does not create response events, send bytes, query storage,
//! or reconstruct invite dependencies. Transit supplies local receive context;
//! the codec supplies canonical dependency ids; the common worker supplies only
//! dependencies that already reached `Applied`.

use super::super::connection_ephemeral_secret;
use super::super::schema as projection;
use super::super::types;
use super::{codec, commands};
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
        commands::validate_invite_signature(&event, &invite_secret)?;
        if let Some(addr) = event.from_listen_addr {
            rows.push(projection::pending_connection_response_row(
                request_id, addr,
            ));
        }
    } else {
        // Local requests have the private ephemeral event as ordinary
        // dependency context. The receiver cannot have that dependency; it
        // validates the public key through the bootstrap receive proof instead.
        let ephemeral = envelope
            .context
            .dependency(&event.initiator_ephemeral_secret_event_id)
            .ok_or_else(|| "connection request missing ephemeral dependency".to_string())?;
        let ephemeral = connection_ephemeral_secret::codec::decode(&ephemeral.canonical_bytes)
            .map_err(|_| "connection request dependency is not an ephemeral secret".to_string())?;
        if ephemeral.owner_endpoint != event.from_endpoint {
            return Err("connection request ephemeral owner does not match sender".to_string());
        }
        if ephemeral.ephemeral_public_key != event.initiator_ephemeral_public_key {
            return Err(
                "connection request ephemeral public key does not match dependency".to_string(),
            );
        }
        let invite_secret = envelope
            .context
            .dependency(&event.invite_secret_event_id)
            .ok_or_else(|| "connection request missing invite secret dependency".to_string())?;
        let invite_secret = invite::codec::decode(&invite_secret.canonical_bytes)
            .map_err(|_| "connection request dependency is not an invite secret".to_string())?;
        commands::validate_invite_signature(&event, &invite_secret)?;
        if let Some(addr) = invite_secret.addr {
            rows.push(projection::pending_connection_attempt_row(request_id, addr));
        }
    }

    Ok(ProjectionOutput::rows(rows))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::protocol::event_modules::connection::connection_ephemeral_secret;
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
            invite_event_id: [3; 32],
            bootstrap_hash: [4; 32],
            invite_signature: [5; crate::core::crypto::ED25519_SIGNATURE_BYTES],
            invite_secret_event_id: [5; 32],
            initiator_ephemeral_secret_event_id: [6; 32],
            initiator_ephemeral_public_key: [7; 32],
            from_listen_addr: None,
        }))
        .expect("request record")
    }

    fn context_with_dependency<'a>(
        record: &'a Record,
        invite_secret_event_id: [u8; 32],
        invite_record: Record,
        ephemeral_secret_event_id: [u8; 32],
        ephemeral_record: Record,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: types::event_id(&record.canonical_bytes),
                dependencies: vec![
                    DependencyContext {
                        event_id: invite_secret_event_id,
                        record: invite_record,
                    },
                    DependencyContext {
                        event_id: ephemeral_secret_event_id,
                        record: ephemeral_record,
                    },
                ],
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    fn authorized_request_record() -> (Record, [u8; 32], Record, [u8; 32], Record) {
        authorized_request_record_for(invite::types::InviteSecretEvent::new([7; 32]))
    }

    fn scoped_authorized_request_record() -> (Record, [u8; 32], Record, [u8; 32], Record) {
        authorized_request_record_for(invite::types::InviteSecretEvent::scoped(
            [7; 32], [6; 32], [5; 32],
        ))
    }

    fn authorized_request_record_for(
        invite_secret: invite::types::InviteSecretEvent,
    ) -> (Record, [u8; 32], Record, [u8; 32], Record) {
        authorized_request_record_for_listen(invite_secret, None)
    }

    fn authorized_request_record_for_listen(
        invite_secret: invite::types::InviteSecretEvent,
        from_listen_addr: Option<SocketAddr>,
    ) -> (Record, [u8; 32], Record, [u8; 32], Record) {
        let invite_record = invite::codec::record_from_bytes(invite::codec::encode(&invite_secret))
            .expect("invite record");
        let invite_secret_event_id = types::event_id(&invite_record.canonical_bytes);
        let ephemeral = connection_ephemeral_secret::types::EphemeralSecretEvent {
            owner_endpoint: [1; 32],
            ephemeral_private_key: [8; 32],
            ephemeral_public_key: crate::core::crypto::x25519_public_key(&[8; 32]),
            created_at_ms: 0,
        };
        let ephemeral_record = connection_ephemeral_secret::codec::record_from_bytes(
            connection_ephemeral_secret::codec::encode(&ephemeral),
        )
        .expect("ephemeral record");
        let ephemeral_secret_event_id = types::event_id(&ephemeral_record.canonical_bytes);
        let request = commands::sign_with_invite(
            RequestEvent {
                from_endpoint: [1; 32],
                to_endpoint: [9; 32],
                nonce: [2; 32],
                invite_event_id: invite_secret.invite_event_id.unwrap_or([3; 32]),
                bootstrap_hash: invite_secret.bootstrap_hash,
                invite_signature: [0; crate::core::crypto::ED25519_SIGNATURE_BYTES],
                invite_secret_event_id,
                initiator_ephemeral_secret_event_id: ephemeral_secret_event_id,
                initiator_ephemeral_public_key: ephemeral.ephemeral_public_key,
                from_listen_addr,
            },
            &invite_secret,
        )
        .expect("sign with invite");
        let record = codec::record_from_bytes(codec::encode(&request)).expect("request record");
        (
            record,
            invite_secret_event_id,
            invite_record,
            ephemeral_secret_event_id,
            ephemeral_record,
        )
    }

    #[test]
    fn projects_request_bytes_without_receive_metadata() {
        let (record, invite_secret_event_id, invite_record, ephemeral_id, ephemeral_record) =
            authorized_request_record();
        let output = project(&context_with_dependency(
            &record,
            invite_secret_event_id,
            invite_record,
            ephemeral_id,
            ephemeral_record,
        ))
        .expect("project request");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[0].key, types::event_id(&record.canonical_bytes));
        assert_eq!(output.rows[0].value, record.canonical_bytes);
    }

    #[test]
    fn local_request_with_invite_addr_queues_pending_connection_attempt() {
        let addr = "127.0.0.1:41000".parse::<SocketAddr>().expect("addr");
        let (record, invite_secret_event_id, invite_record, ephemeral_id, ephemeral_record) =
            authorized_request_record_for(invite::types::InviteSecretEvent::new_with_addr(
                [7; 32], addr,
            ));

        let output = project(&context_with_dependency(
            &record,
            invite_secret_event_id,
            invite_record,
            ephemeral_id,
            ephemeral_record,
        ))
        .expect("project request");

        assert_eq!(output.rows.len(), 2);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[1].table, schema::PENDING_CONNECTION_ATTEMPTS);
        assert_eq!(output.rows[1].key, types::event_id(&record.canonical_bytes));
        assert_eq!(output.rows[1].value, addr.to_string().into_bytes());
    }

    #[test]
    fn local_scoped_request_only_caches_request_bytes() {
        let (record, invite_secret_event_id, invite_record, ephemeral_id, ephemeral_record) =
            scoped_authorized_request_record();
        let output = project(&context_with_dependency(
            &record,
            invite_secret_event_id,
            invite_record,
            ephemeral_id,
            ephemeral_record,
        ))
        .expect("project local scoped request");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
    }

    #[test]
    fn projects_received_request_bytes_without_private_ephemeral_dependency() {
        let (record, invite_secret_event_id, invite_record, _, _) = authorized_request_record();
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

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
    }

    #[test]
    fn received_request_with_listen_addr_queues_pending_connection_response() {
        let listen = "127.0.0.1:41001".parse::<SocketAddr>().expect("addr");
        let (record, invite_secret_event_id, invite_record, _, _) =
            authorized_request_record_for_listen(
                invite::types::InviteSecretEvent::new([7; 32]),
                Some(listen),
            );
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

        assert_eq!(output.rows.len(), 2);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[1].table, schema::PENDING_CONNECTION_RESPONSES);
        assert_eq!(output.rows[1].key, types::event_id(&record.canonical_bytes));
        assert_eq!(output.rows[1].value, listen.to_string().into_bytes());
    }

    #[test]
    fn received_scoped_request_only_caches_request_bytes() {
        let (record, invite_secret_event_id, invite_record, _, _) =
            scoped_authorized_request_record();
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
        .expect("project received scoped request");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
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
        let (record, _, _, _, _) = authorized_request_record();

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
        let (record, invite_secret_event_id, _, _, _) = authorized_request_record();
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

    #[test]
    fn rejects_scoped_request_when_invite_id_does_not_match() {
        let (record, invite_secret_event_id, invite_record, _, _) =
            scoped_authorized_request_record();
        let mut request = codec::decode(&record.canonical_bytes).expect("decode request");
        request.invite_event_id = [9; 32];
        let record = codec::record_from_bytes(codec::encode(&request)).expect("tampered request");

        assert_eq!(
            project(&EventWithContext {
                record: &record,
                context: EventContext {
                    event_id: types::event_id(&record.canonical_bytes),
                    dependencies: vec![DependencyContext {
                        event_id: invite_secret_event_id,
                        record: invite_record,
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
            .expect_err("wrong invite id must fail"),
            "connection request invite id is not authorized"
        );
    }

    #[test]
    fn rejects_received_request_when_invite_signature_does_not_match() {
        let (record, invite_secret_event_id, invite_record, _, _) = authorized_request_record();
        let mut request = codec::decode(&record.canonical_bytes).expect("decode request");
        request.invite_signature = [9; crate::core::crypto::ED25519_SIGNATURE_BYTES];
        let record = codec::record_from_bytes(codec::encode(&request)).expect("tampered request");

        assert_eq!(
            project(&EventWithContext {
                record: &record,
                context: EventContext {
                    event_id: types::event_id(&record.canonical_bytes),
                    dependencies: vec![DependencyContext {
                        event_id: invite_secret_event_id,
                        record: invite_record,
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
            .expect_err("wrong invite signature must fail"),
            "connection request invite signature is not authorized"
        );
    }
}
