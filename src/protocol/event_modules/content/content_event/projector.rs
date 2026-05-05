//! Projector for signed workspace-scoped content events.
//!
//! Content is ordinary shared history, so the event carries a workspace id and is
//! sync-scoped by that id. Its authority is not the transport endpoint key used
//! to open a connection; it is the Ed25519 signing key published by an
//! endpoint_shared event in the same workspace.

use crate::protocol::event_modules::identity::{endpoint_shared, signed};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let content = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(content.workspace_id) {
        return Err("content workspace metadata does not match event body".to_string());
    }

    let signer = event
        .context
        .dependency(&envelope.signer_endpoint_shared_id)
        .ok_or_else(|| "content signer endpoint_shared dependency is missing".to_string())?;
    let signer_envelope = signed::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "content signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err("content signer dependency is not a signed endpoint_shared".to_string());
    }
    let signer_endpoint_shared = endpoint_shared::codec::decode(&signer_envelope.payload)
        .map_err(|_| "content signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_endpoint_shared.workspace_id != content.workspace_id {
        return Err("content signer endpoint_shared workspace does not match content".to_string());
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err("content signer public key does not match endpoint_shared".to_string());
    }

    Ok(ProjectionOutput::rows(vec![schema::content_event_row(
        event.context.event_id,
        &content,
    )]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::endpoint_shared;
    use crate::protocol::event_modules::types::{event_id, EventScope};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::ContentEvent;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn event(workspace_id: [u8; 32]) -> (Record, [u8; 32], [u8; 32], Record) {
        let signer_private_key = [9; 32];
        let signer_public_key = signing_public_key_for(&signer_private_key);
        let signer = endpoint_shared_record(workspace_id, signer_public_key);
        let signer_id = event_id(&signer.canonical_bytes);
        let payload = codec::encode(&ContentEvent {
            workspace_id,
            timestamp: 5,
            payload: vec![1, 2, 3],
        });
        let envelope = codec::sign(signer_id, &signer_private_key, payload);
        let bytes = codec::encode_signed(&envelope);
        let id = event_id(&bytes);
        (
            codec::signed_record_from_bytes(bytes).expect("record"),
            id,
            signer_id,
            signer,
        )
    }

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        codec::sign([0; 32], private_key, vec![codec::TYPE_CONTENT]).signer_public_key
    }

    fn endpoint_shared_record(workspace_id: [u8; 32], signing_public_key: [u8; 32]) -> Record {
        let payload =
            endpoint_shared::codec::encode(&endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id: [8; 32],
                endpoint_id: [7; 32],
                signing_public_key,
                device_name: "laptop".to_string(),
            })
            .expect("encode endpoint_shared");
        let signed = signed::commands::sign_payload([6; 32], &[5; 32], payload)
            .expect("sign endpoint_shared");
        signed.events[0].record().clone()
    }

    fn context_for<'a>(
        record: &'a Record,
        event_id: [u8; 32],
        signer_id: [u8; 32],
        signer: Record,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id,
                dependencies: vec![DependencyContext {
                    event_id: signer_id,
                    record: signer,
                }],
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    #[test]
    fn projects_one_content_row_scoped_by_workspace() {
        let (record, event_id, signer_id, signer) = event([7; 32]);
        let event = context_for(&record, event_id, signer_id, signer);

        let output = project(&event).expect("project content");

        assert_eq!(output.labels.len(), 0);
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::CONTENT_EVENTS);
        let row = schema::decode_content_event_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, [7; 32]);
        assert_eq!(row.event_id, event_id);
        assert_eq!(row.payload_bytes, 3);
    }

    #[test]
    fn rejects_mismatched_workspace_metadata() {
        let (mut record, event_id, signer_id, signer) = event([7; 32]);
        record.workspace_id = Some([8; 32]);
        let event = context_for(&record, event_id, signer_id, signer);

        assert_eq!(
            project(&event).expect_err("mismatch must fail"),
            "content workspace metadata does not match event body"
        );
    }

    #[test]
    fn rejects_missing_signer_endpoint_shared_dependency() {
        let (record, event_id, _, _) = event([7; 32]);
        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id,
                dependencies: Vec::new(),
                labels: Vec::new(),
                receive: None,
            },
        };

        assert_eq!(
            project(&event).expect_err("missing signer must fail"),
            "content signer endpoint_shared dependency is missing"
        );
    }

    #[test]
    fn rejects_signer_for_another_workspace() {
        let (record, event_id, signer_id, _) = event([7; 32]);
        let signer = endpoint_shared_record(
            [8; 32],
            codec::decode_signed(&record.canonical_bytes)
                .expect("decode signed content")
                .signer_public_key,
        );
        let event = context_for(&record, event_id, signer_id, signer);

        assert_eq!(
            project(&event).expect_err("wrong workspace must fail"),
            "content signer endpoint_shared workspace does not match content"
        );
    }

    #[test]
    fn rejects_signer_public_key_mismatch() {
        let (record, event_id, signer_id, _) = event([7; 32]);
        let signer = endpoint_shared_record([7; 32], signing_public_key_for(&[10; 32]));
        let event = context_for(&record, event_id, signer_id, signer);

        assert_eq!(
            project(&event).expect_err("wrong signer key must fail"),
            "content signer public key does not match endpoint_shared"
        );
    }

    #[test]
    fn record_exposes_signer_and_workspace_dependencies_and_metadata() {
        let (record, _, signer_id, _) = event([7; 32]);

        assert_eq!(record.dependencies, vec![signer_id, [7; 32]]);
        assert_eq!(record.workspace_id, Some([7; 32]));
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn raw_content_bytes_are_not_admissible_protocol_events() {
        let raw = codec::encode(&ContentEvent {
            workspace_id: [7; 32],
            timestamp: 5,
            payload: vec![1, 2, 3],
        });

        assert_eq!(
            crate::protocol::event_modules::record_from_bytes(raw)
                .expect_err("raw content must fail"),
            "content must be signed"
        );
    }
}
