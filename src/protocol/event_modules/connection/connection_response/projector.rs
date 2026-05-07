//! Projector for connection response events.
//!
//! Responses are connection facts, not transport effects. They answer a
//! specific request and commit the responder to the connection id derived from
//! that request.
//!
//! This projector has two legal modes:
//!
//! ```text
//! local response, no receive metadata
//!   -> verify request dependency
//!   -> store response bytes only
//!
//! received response, with endpoint receive metadata
//!   -> verify request dependency
//!   -> verify response endpoint direction and derived connection id
//!   -> verify receive endpoint/sender/authorization
//!   -> store response bytes
//!   -> project connection(response.connection_id, response.from_endpoint)
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

use super::super::connection_request;
use super::super::schema as projection;
use super::super::types;
use super::codec;
use crate::protocol::event_modules::types::ReceiveAuthorization;

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = event.record.canonical_bytes.clone();
    let receive = event.context.receive;
    let response = codec::decode(&bytes)?;
    // The response body carries a connection id, but that id is accepted only
    // if it is exactly the deterministic id for the request and responder.
    let expected_connection_id =
        types::connection_id(&response.request_id, &response.from_endpoint);
    if response.connection_id != expected_connection_id {
        return Err("connection response has an invalid connection id".to_string());
    }
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

    // Always cache the canonical response bytes so future facts can depend on
    // exactly this response event if the protocol starts using that edge.
    let mut rows = vec![projection::connection_event_row(
        types::event_id(&bytes),
        bytes,
    )];
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
        // The route and remote endpoint row are local projections from a
        // response that has passed both dependency validation and receive
        // provenance validation.
        rows.push(projection::connection_row(
            response.connection_id,
            response.from_endpoint,
        ));
        if receive.remember_route() {
            // Route learning remains subjective metadata; it is never encoded
            // into the response fact and is only written when the worker marks
            // the observed route as reusable.
            rows.push(projection::transport_target_row(
                response.connection_id,
                receive.origin(),
            ));
        }
    }
    Ok(ProjectionOutput::rows(rows))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::protocol::event_modules::connection::connection_response::types::ResponseEvent;
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
                invite_secret_event_id: [7; 32],
                from_listen_addr: None,
            },
        ))
        .expect("request record")
    }

    fn response_record(request_id: [u8; 32]) -> Record {
        let response = ResponseEvent {
            from_endpoint: [4; 32],
            to_endpoint: [1; 32],
            request_id,
            connection_id: types::connection_id(&request_id, &[4; 32]),
        };
        codec::record_from_bytes(codec::encode(&response)).expect("response record")
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
    fn projects_response_bytes_with_matching_request_dependency() {
        let request = request_record();
        let request_id = types::event_id(&request.canonical_bytes);
        let response = response_record(request_id);

        let output =
            project(&context_for(&response, request_id, request)).expect("project response");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(
            output.rows[0].key,
            types::event_id(&response.canonical_bytes)
        );
        assert_eq!(output.rows[0].value, response.canonical_bytes);
    }

    #[test]
    fn projects_received_response_connection_and_route_rows() {
        let request = request_record();
        let request_id = types::event_id(&request.canonical_bytes);
        let response = response_record(request_id);
        let origin = "127.0.0.1:9001".parse::<SocketAddr>().expect("addr");

        let output = project(&EventWithContext {
            record: &response,
            context: EventContext {
                event_id: types::event_id(&response.canonical_bytes),
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
        .expect("project response");

        assert_eq!(output.rows.len(), 3);
        assert_eq!(output.rows[0].table, schema::CONNECTION_EVENTS);
        assert_eq!(output.rows[1].table, schema::CONNECTIONS);
        assert_eq!(output.rows[2].table, schema::TRANSPORT_TARGETS);
        assert_eq!(output.rows[1].value, [4; 32]);
        assert_eq!(output.rows[2].value, origin.to_string().into_bytes());
    }

    #[test]
    fn rejects_response_for_another_endpoint_request() {
        let request = connection_request::codec::record_from_bytes(
            connection_request::codec::encode(&connection_request::types::RequestEvent {
                from_endpoint: [8; 32],
                to_endpoint: [4; 32],
                nonce: [2; 32],
                bootstrap_hash: [3; 32],
                invite_secret_event_id: [7; 32],
                from_listen_addr: None,
            }),
        )
        .expect("request record");
        let request_id = types::event_id(&request.canonical_bytes);
        let response = response_record(request_id);

        let err = project(&context_for(&response, request_id, request)).expect_err("reject");
        assert!(err.contains("another endpoint"));
    }

    #[test]
    fn rejects_received_response_without_endpoint_receive_authorization() {
        let request = request_record();
        let request_id = types::event_id(&request.canonical_bytes);
        let response = response_record(request_id);

        assert_eq!(
            project(&EventWithContext {
                record: &response,
                context: EventContext {
                    event_id: types::event_id(&response.canonical_bytes),
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
                    )),
                },
            })
            .expect_err("unauthorized response receive must fail"),
            "connection response requires endpoint receive authorization"
        );
    }

    #[test]
    fn rejects_received_response_when_receive_sender_does_not_match_response_sender() {
        let request = request_record();
        let request_id = types::event_id(&request.canonical_bytes);
        let response = response_record(request_id);

        assert_eq!(
            project(&EventWithContext {
                record: &response,
                context: EventContext {
                    event_id: types::event_id(&response.canonical_bytes),
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
            "connection response sender does not match receive sender"
        );
    }
}
