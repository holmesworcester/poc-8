//! Projector for connection request events.
//!
//! The projector writes the request bytes for later validation. When the common
//! worker supplies receive metadata, the same projection also learns the
//! subjective local connection fact: "this endpoint received the request from
//! this route." That keeps route learning atomic with connection establishment
//! without turning socket addresses into separate semantic events.

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
    let mut rows = vec![projection::connection_event_row(request_id, bytes)];
    if let Some(receive) = receive {
        // A received request establishes a route only when the connection worker
        // supplied bootstrap-invite authorization. The canonical request bytes
        // alone are not enough: anyone can name a bootstrap hash, but only a peer
        // that proved knowledge of the invite secret over the receive boundary
        // gets receive metadata naming the local secret event dependency.
        if event.to_endpoint != receive.local_endpoint() {
            return Err("connection request addressed to a different endpoint".to_string());
        }
        if event.from_endpoint != receive.remote_endpoint() {
            return Err("connection request sender does not match receive sender".to_string());
        }
        let ReceiveAuthorization::BootstrapInvite {
            invite_secret_event_id,
        } = receive.authorization()
        else {
            return Err("connection request requires bootstrap invite authorization".to_string());
        };
        let invite_secret = envelope
            .context
            .dependency(&invite_secret_event_id)
            .ok_or_else(|| "connection request missing invite secret dependency".to_string())?;
        let invite_secret = invite::codec::decode(&invite_secret.canonical_bytes)
            .map_err(|_| "connection request dependency is not an invite secret".to_string())?;
        if invite_secret.bootstrap_hash != event.bootstrap_hash {
            return Err("connection request bootstrap hash is not authorized".to_string());
        }
        let connection_id = types::connection_id(&request_id, &receive.local_endpoint());
        rows.push(projection::connection_row(
            connection_id,
            event.from_endpoint,
        ));
        if receive.remember_route() {
            rows.push(projection::transport_target_row(
                connection_id,
                receive.origin(),
            ));
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
        }))
        .expect("request record")
    }

    fn context_for(record: &Record) -> EventWithContext<'_> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: types::event_id(&record.canonical_bytes),
                dependencies: Vec::new(),
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    fn authorized_request_record() -> (Record, [u8; 32], Record) {
        let invite_secret = invite::types::InviteSecretEvent::new([7; 32]);
        let invite_record = invite::codec::record_from_bytes(invite::codec::encode(&invite_secret))
            .expect("invite record");
        let invite_secret_event_id = types::event_id(&invite_record.canonical_bytes);
        let mut record = codec::record_from_bytes(codec::encode(&RequestEvent {
            from_endpoint: [1; 32],
            to_endpoint: [9; 32],
            nonce: [2; 32],
            bootstrap_hash: invite_secret.bootstrap_hash,
        }))
        .expect("request record");
        record.dependencies.push(invite_secret_event_id);
        (record, invite_secret_event_id, invite_record)
    }

    #[test]
    fn projects_request_bytes_without_receive_metadata() {
        let record = request_record();
        let output = project(&context_for(&record)).expect("project request");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[0].key, types::event_id(&record.canonical_bytes));
        assert_eq!(output.rows[0].value, record.canonical_bytes);
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
                    origin,
                    [9; 32],
                    [1; 32],
                    true,
                    invite_secret_event_id,
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
        let (record, invite_secret_event_id, _) = authorized_request_record();

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
                        invite_secret_event_id,
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
                        invite_secret_event_id,
                    )),
                },
            })
            .expect_err("wrong invite dependency must fail"),
            "connection request bootstrap hash is not authorized"
        );
    }
}
