//! Projector for connection ack events.
//!
//! Acks are connection facts, not transport effects. Locally-created acks only
//! record their bytes. Received acks carry receive metadata from the worker; in
//! that case projection records the established connection and the route we just
//! observed in the same row output.

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::super::connection_request;
use super::super::schema as projection;
use super::super::types;
use super::codec;
use crate::protocol::event_modules::types::ReceiveAuthorization;

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = event.record.canonical_bytes.clone();
    let receive = event.context.receive;
    let ack = codec::decode(&bytes)?;
    let expected_connection_id = types::connection_id(&ack.request_id, &ack.from_endpoint);
    if ack.connection_id != expected_connection_id {
        return Err("connection ack has an invalid connection id".to_string());
    }
    let request = event
        .context
        .dependency(&ack.request_id)
        .ok_or_else(|| "connection ack missing request dependency".to_string())?;
    let request = connection_request::codec::decode(&request.canonical_bytes)
        .map_err(|_| "connection ack references a non-request event".to_string())?;
    if request.from_endpoint != ack.to_endpoint {
        return Err("connection ack references another endpoint's request".to_string());
    }
    if request.to_endpoint != ack.from_endpoint {
        return Err("connection ack sender does not match request recipient".to_string());
    }

    let mut rows = vec![projection::connection_event_row(
        types::event_id(&bytes),
        bytes,
    )];
    if let Some(receive) = receive {
        // A received ack can establish a route only for an already authenticated
        // endpoint receive. Bootstrap authorization is consumed by the request;
        // from this point forward the route is tied to the endpoint pair and
        // connection id derived from that request/ack pair.
        if ack.to_endpoint != receive.local_endpoint() {
            return Err("connection ack addressed to a different endpoint".to_string());
        }
        if ack.from_endpoint != receive.remote_endpoint() {
            return Err("connection ack sender does not match receive sender".to_string());
        }
        if receive.authorization() != ReceiveAuthorization::EndpointReceive {
            return Err("connection ack requires endpoint receive authorization".to_string());
        }
        rows.push(projection::connection_row(
            ack.connection_id,
            ack.from_endpoint,
        ));
        if receive.remember_route() {
            rows.push(projection::transport_target_row(
                ack.connection_id,
                receive.origin(),
            ));
        }
    }
    Ok(ProjectionOutput::rows(rows))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::protocol::event_modules::connection::connection_ack::types::AckEvent;
    use crate::protocol::event_modules::connection::{connection_request, schema, types};
    use crate::protocol::event_modules::types::ReceiveMetadata;
    use crate::protocol::event_modules::worker::{DependencyContext, EventContext};

    use super::codec;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn request_record() -> Record {
        connection_request::codec::record_from_bytes(connection_request::codec::encode(
            &connection_request::types::RequestEvent {
                from_endpoint: [1; 32],
                to_endpoint: [4; 32],
                nonce: [2; 32],
                bootstrap_hash: [3; 32],
            },
        ))
        .expect("request record")
    }

    fn ack_record(request_id: [u8; 32]) -> Record {
        let ack = AckEvent {
            from_endpoint: [4; 32],
            to_endpoint: [1; 32],
            request_id,
            connection_id: types::connection_id(&request_id, &[4; 32]),
        };
        codec::record_from_bytes(codec::encode(&ack)).expect("ack record")
    }

    fn context_for<'a>(
        record: &'a Record,
        request_id: [u8; 32],
        request_record: Record,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: types::event_id(&record.canonical_bytes),
                dependencies: vec![DependencyContext {
                    event_id: request_id,
                    record: request_record,
                }],
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    #[test]
    fn projects_ack_bytes_with_matching_request_dependency() {
        let request = request_record();
        let request_id = types::event_id(&request.canonical_bytes);
        let ack = ack_record(request_id);

        let output = project(&context_for(&ack, request_id, request)).expect("project ack");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[0].key, types::event_id(&ack.canonical_bytes));
        assert_eq!(output.rows[0].value, ack.canonical_bytes);
    }

    #[test]
    fn projects_received_ack_connection_and_route_rows() {
        let request = request_record();
        let request_id = types::event_id(&request.canonical_bytes);
        let ack = ack_record(request_id);
        let origin = "127.0.0.1:9001".parse::<SocketAddr>().expect("addr");

        let output = project(&EventWithContext {
            record: &ack,
            context: EventContext {
                event_id: types::event_id(&ack.canonical_bytes),
                dependencies: vec![DependencyContext {
                    event_id: request_id,
                    record: request,
                }],
                labels: Vec::new(),
                receive: Some(ReceiveMetadata::endpoint_receive(
                    origin, [1; 32], [4; 32], true,
                )),
            },
        })
        .expect("project ack");

        assert_eq!(output.rows.len(), 3);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[1].table, schema::CONNECTIONS);
        assert_eq!(output.rows[2].table, schema::TRANSPORT_TARGETS);
        assert_eq!(output.rows[1].value, [4; 32]);
        assert_eq!(output.rows[2].value, origin.to_string().into_bytes());
    }

    #[test]
    fn rejects_ack_for_another_endpoint_request() {
        let request = connection_request::codec::record_from_bytes(
            connection_request::codec::encode(&connection_request::types::RequestEvent {
                from_endpoint: [8; 32],
                to_endpoint: [4; 32],
                nonce: [2; 32],
                bootstrap_hash: [3; 32],
            }),
        )
        .expect("request record");
        let request_id = types::event_id(&request.canonical_bytes);
        let ack = ack_record(request_id);

        let err = project(&context_for(&ack, request_id, request)).expect_err("reject");
        assert!(err.contains("another endpoint"));
    }

    #[test]
    fn rejects_received_ack_without_endpoint_receive_authorization() {
        let request = request_record();
        let request_id = types::event_id(&request.canonical_bytes);
        let ack = ack_record(request_id);

        assert_eq!(
            project(&EventWithContext {
                record: &ack,
                context: EventContext {
                    event_id: types::event_id(&ack.canonical_bytes),
                    dependencies: vec![DependencyContext {
                        event_id: request_id,
                        record: request,
                    }],
                    labels: Vec::new(),
                    receive: Some(ReceiveMetadata::bootstrap_invite(
                        "127.0.0.1:9001".parse::<SocketAddr>().expect("addr"),
                        [1; 32],
                        [4; 32],
                        true,
                        [7; 32],
                    )),
                },
            })
            .expect_err("unauthorized ack receive must fail"),
            "connection ack requires endpoint receive authorization"
        );
    }

    #[test]
    fn rejects_received_ack_when_receive_sender_does_not_match_ack_sender() {
        let request = request_record();
        let request_id = types::event_id(&request.canonical_bytes);
        let ack = ack_record(request_id);

        assert_eq!(
            project(&EventWithContext {
                record: &ack,
                context: EventContext {
                    event_id: types::event_id(&ack.canonical_bytes),
                    dependencies: vec![DependencyContext {
                        event_id: request_id,
                        record: request,
                    }],
                    labels: Vec::new(),
                    receive: Some(ReceiveMetadata::endpoint_receive(
                        "127.0.0.1:9001".parse::<SocketAddr>().expect("addr"),
                        [1; 32],
                        [99; 32],
                        true,
                    )),
                },
            })
            .expect_err("wrong receive sender must fail"),
            "connection ack sender does not match receive sender"
        );
    }
}
