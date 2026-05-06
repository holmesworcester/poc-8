//! Projector for signed key-wrap events.
//!
//! Projection proves that the signer endpoint membership, removal frontier, and
//! recipient key all live in the same workspace, then records the wrap and the
//! local key-secret commitment it carries. It does not open the ciphertext or
//! create local key-secret events; the domain worker performs that active step
//! after local recipient material is available.

use crate::protocol::event_modules::identity::{endpoint_shared, signed};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::super::{recipient_key, removal_frontier};
use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let key_wrap = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(key_wrap.workspace_id) {
        return Err("key wrap workspace metadata does not match event body".to_string());
    }

    let signer_endpoint_shared =
        decode_signer_endpoint_shared(event, envelope.signer_endpoint_shared_id)?;
    if signer_endpoint_shared.workspace_id != key_wrap.workspace_id {
        return Err("key wrap signer endpoint_shared workspace does not match event".to_string());
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err("key wrap signer public key does not match endpoint_shared".to_string());
    }

    let frontier = decode_removal_frontier(event, key_wrap.removal_frontier_id)?;
    if frontier.workspace_id != key_wrap.workspace_id {
        return Err("key wrap removal frontier workspace does not match event".to_string());
    }

    let recipient = decode_recipient_key(event, key_wrap.recipient_key_id)?;
    if recipient.workspace_id != key_wrap.workspace_id {
        return Err("key wrap recipient key workspace does not match event".to_string());
    }

    Ok(ProjectionOutput::rows(vec![
        schema::key_secret_commitment_row(&key_wrap),
        schema::key_wrap_row(
            event.context.event_id,
            envelope.signer_endpoint_shared_id,
            envelope.signer_public_key,
            &key_wrap,
        ),
    ]))
}

fn decode_signer_endpoint_shared(
    event: &EventWithContext<'_>,
    endpoint_shared_id: [u8; 32],
) -> Result<endpoint_shared::types::EndpointSharedEvent, String> {
    let record = event
        .context
        .dependency(&endpoint_shared_id)
        .ok_or_else(|| "key wrap signer endpoint_shared dependency is missing".to_string())?;
    let envelope = signed::codec::decode(&record.canonical_bytes)
        .map_err(|_| "key wrap signer dependency is not a signed endpoint_shared".to_string())?;
    if envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err("key wrap signer dependency is not a signed endpoint_shared".to_string());
    }
    endpoint_shared::codec::decode(&envelope.payload)
        .map_err(|_| "key wrap signer dependency is not a signed endpoint_shared".to_string())
}

fn decode_removal_frontier(
    event: &EventWithContext<'_>,
    removal_frontier_id: [u8; 32],
) -> Result<removal_frontier::types::RemovalFrontierEvent, String> {
    let record = event
        .context
        .dependency(&removal_frontier_id)
        .ok_or_else(|| "key wrap removal frontier dependency is missing".to_string())?;
    let envelope = removal_frontier::codec::decode_signed(&record.canonical_bytes)
        .map_err(|_| "key wrap dependency is not a removal frontier".to_string())?;
    removal_frontier::codec::decode(&envelope.payload)
        .map_err(|_| "key wrap dependency is not a removal frontier".to_string())
}

fn decode_recipient_key(
    event: &EventWithContext<'_>,
    recipient_key_id: [u8; 32],
) -> Result<recipient_key::types::RecipientKeyEvent, String> {
    let record = event
        .context
        .dependency(&recipient_key_id)
        .ok_or_else(|| "key wrap recipient key dependency is missing".to_string())?;
    let envelope = recipient_key::codec::decode_signed(&record.canonical_bytes)
        .map_err(|_| "key wrap dependency is not a recipient key".to_string())?;
    recipient_key::codec::decode(&envelope.payload)
        .map_err(|_| "key wrap dependency is not a recipient key".to_string())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{endpoint_shared, signed};
    use crate::protocol::event_modules::types::{event_id, EventId};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::super::{local_key_secret, local_recipient_key};
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signer_public_key(private_key: &[u8; 32]) -> [u8; 32] {
        signed::commands::sign_payload([0; 32], private_key, vec![99])
            .expect("sign fixture")
            .value
            .signer_public_key
    }

    fn endpoint_shared_record(workspace_id: [u8; 32], signing_public_key: [u8; 32]) -> Record {
        let payload =
            endpoint_shared::codec::encode(&endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id: [3; 32],
                endpoint_id: [21; 32],
                signing_public_key,
                endpoint_role:
                    crate::protocol::event_modules::identity::endpoint::types::EndpointRole::Device,
                device_name: "laptop".to_string(),
            })
            .expect("encode endpoint_shared");
        signed::commands::sign_payload([6; 32], &[5; 32], payload)
            .expect("sign endpoint_shared")
            .events[0]
            .record()
            .clone()
    }

    fn frontier_record(workspace_id: [u8; 32]) -> (EventId, Record) {
        let record =
            removal_frontier::commands::create(removal_frontier::commands::CreateRemovalFrontier {
                workspace_id,
                created_at_ms: 5,
                authority_admin_id: [3; 32],
                signer_endpoint_shared_id: [4; 32],
                signer_private_key: [9; 32],
                removal_event_ids: Vec::new(),
            })
            .expect("create frontier")
            .events[0]
                .record()
                .clone();
        (event_id(&record.canonical_bytes), record)
    }

    fn recipient_record(workspace_id: [u8; 32], signer_id: [u8; 32]) -> (EventId, Record) {
        let local = local_recipient_key::commands::create(workspace_id)
            .expect("local recipient")
            .value;
        let record =
            recipient_key::commands::publish(recipient_key::commands::PublishRecipientKey {
                workspace_id,
                created_at_ms: 6,
                endpoint_shared_id: signer_id,
                signer_private_key: [9; 32],
                recipient_key: local.recipient_key,
            })
            .expect("publish")
            .events[0]
                .record()
                .clone();
        (event_id(&record.canonical_bytes), record)
    }

    fn key_wrap_record(
        workspace_id: [u8; 32],
        signer_id: [u8; 32],
        frontier_id: [u8; 32],
        recipient_id: [u8; 32],
        recipient_record: &Record,
    ) -> Record {
        let recipient = recipient_key::codec::decode(
            &recipient_key::codec::decode_signed(&recipient_record.canonical_bytes)
                .expect("signed recipient")
                .payload,
        )
        .expect("recipient");
        let local_secret =
            local_key_secret::commands::from_key_secret(workspace_id, frontier_id, [7; 32])
                .expect("local secret")
                .value;
        super::super::commands::create(super::super::commands::CreateKeyWrap {
            workspace_id,
            created_at_ms: 7,
            signer_endpoint_shared_id: signer_id,
            signer_private_key: [9; 32],
            removal_frontier_id: frontier_id,
            local_key_secret_id: local_secret.local_key_secret_id,
            key_secret: local_secret.event.key_secret,
            recipient_key_id: recipient_id,
            recipient_key: recipient.recipient_key,
        })
        .expect("wrap")
        .events[0]
            .record()
            .clone()
    }

    fn event_with_context<'a>(
        record: &'a Record,
        signer_id: [u8; 32],
        signer_record: Record,
        frontier_id: [u8; 32],
        frontier_record: Record,
        recipient_id: [u8; 32],
        recipient_record: Record,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: vec![
                    DependencyContext {
                        event_id: signer_id,
                        record: signer_record,
                    },
                    DependencyContext {
                        event_id: frontier_id,
                        record: frontier_record,
                    },
                    DependencyContext {
                        event_id: recipient_id,
                        record: recipient_record,
                    },
                ],
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    #[test]
    fn projects_key_wrap_row_from_valid_dependencies() {
        let signer_private_key = [9; 32];
        let signer_record = endpoint_shared_record([1; 32], signer_public_key(&signer_private_key));
        let signer_id = event_id(&signer_record.canonical_bytes);
        let (frontier_id, frontier_record) = frontier_record([1; 32]);
        let (recipient_id, recipient_record) = recipient_record([1; 32], signer_id);
        let record = key_wrap_record(
            [1; 32],
            signer_id,
            frontier_id,
            recipient_id,
            &recipient_record,
        );
        let event = event_with_context(
            &record,
            signer_id,
            signer_record,
            frontier_id,
            frontier_record,
            recipient_id,
            recipient_record,
        );

        let output = project(&event).expect("project key wrap");

        assert_eq!(output.rows.len(), 2);
        assert_eq!(output.rows[0].table, schema::KEY_SECRET_COMMITMENTS);
        assert_eq!(output.rows[1].table, schema::KEY_WRAPS);
        let row = schema::decode_key_wrap_row(&output.rows[1].key, &output.rows[1].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, [1; 32]);
        assert_eq!(row.key_wrap_id, event.context.event_id);
        assert_eq!(row.removal_frontier_id, frontier_id);
        assert_eq!(row.recipient_key_id, recipient_id);
    }

    #[test]
    fn rejects_recipient_key_from_other_workspace() {
        let signer_private_key = [9; 32];
        let signer_record = endpoint_shared_record([1; 32], signer_public_key(&signer_private_key));
        let signer_id = event_id(&signer_record.canonical_bytes);
        let (frontier_id, frontier_record) = frontier_record([1; 32]);
        let (recipient_id, recipient_record) = recipient_record([2; 32], signer_id);
        let record = key_wrap_record(
            [1; 32],
            signer_id,
            frontier_id,
            recipient_id,
            &recipient_record,
        );
        let event = event_with_context(
            &record,
            signer_id,
            signer_record,
            frontier_id,
            frontier_record,
            recipient_id,
            recipient_record,
        );

        assert_eq!(
            project(&event).expect_err("wrong recipient workspace must fail"),
            "key wrap recipient key workspace does not match event"
        );
    }
}
