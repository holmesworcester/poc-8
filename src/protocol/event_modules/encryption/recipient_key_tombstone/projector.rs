//! Projector for signed recipient key tombstones.
//!
//! The retiring endpoint must sign the tombstone, and both old and replacement
//! recipient key facts must belong to that same endpoint membership. Projection
//! records the shared retirement fact and removes the old public active row; it
//! does not touch local private rows or derived content keys.

use crate::protocol::event_modules::identity::{endpoint_shared, signed};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput, TableDelete};

use super::super::recipient_key;
use super::types::SignedRecipientKeyTombstoneEnvelope;
use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let tombstone = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(tombstone.workspace_id) {
        return Err(
            "recipient key tombstone workspace metadata does not match event body".to_string(),
        );
    }
    if envelope.signer_endpoint_shared_id != tombstone.endpoint_shared_id {
        return Err("recipient key tombstone signer does not match payload endpoint".to_string());
    }

    let signer_endpoint_shared = decode_signer(event, &envelope)?;
    if signer_endpoint_shared.workspace_id != tombstone.workspace_id {
        return Err(
            "recipient key tombstone signer endpoint_shared workspace does not match event"
                .to_string(),
        );
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err(
            "recipient key tombstone signer public key does not match endpoint_shared".to_string(),
        );
    }

    let old_key = decode_recipient_key(event, tombstone.old_recipient_key_id)?;
    let new_key = decode_recipient_key(event, tombstone.new_recipient_key_id)?;
    if old_key.workspace_id != tombstone.workspace_id
        || new_key.workspace_id != tombstone.workspace_id
    {
        return Err("recipient key tombstone key workspace does not match event".to_string());
    }
    if old_key.endpoint_shared_id != tombstone.endpoint_shared_id
        || new_key.endpoint_shared_id != tombstone.endpoint_shared_id
    {
        return Err("recipient key tombstone keys must belong to signer endpoint".to_string());
    }

    let mut output = ProjectionOutput::rows(vec![schema::recipient_key_tombstone_row(
        event.context.event_id,
        &tombstone,
    )]);
    output.deletes.push(TableDelete {
        table: recipient_key::schema::RECIPIENT_KEYS,
        key: recipient_key::schema::recipient_key_key(
            tombstone.workspace_id,
            tombstone.old_recipient_key_id,
        ),
    });
    Ok(output)
}

fn decode_signer(
    event: &EventWithContext<'_>,
    envelope: &SignedRecipientKeyTombstoneEnvelope,
) -> Result<endpoint_shared::types::EndpointSharedEvent, String> {
    let signer = event
        .context
        .dependency(&envelope.signer_endpoint_shared_id)
        .ok_or_else(|| {
            "recipient key tombstone signer endpoint_shared dependency is missing".to_string()
        })?;
    let signer_envelope = signed::codec::decode(&signer.canonical_bytes).map_err(|_| {
        "recipient key tombstone signer dependency is not a signed endpoint_shared".to_string()
    })?;
    if signer_envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err(
            "recipient key tombstone signer dependency is not a signed endpoint_shared".to_string(),
        );
    }
    endpoint_shared::codec::decode(&signer_envelope.payload).map_err(|_| {
        "recipient key tombstone signer dependency is not a signed endpoint_shared".to_string()
    })
}

fn decode_recipient_key(
    event: &EventWithContext<'_>,
    recipient_key_id: [u8; 32],
) -> Result<recipient_key::types::RecipientKeyEvent, String> {
    let record = event
        .context
        .dependency(&recipient_key_id)
        .ok_or_else(|| "recipient key tombstone key dependency is missing".to_string())?;
    let envelope = recipient_key::codec::decode_signed(&record.canonical_bytes)
        .map_err(|_| "recipient key tombstone dependency is not a recipient key".to_string())?;
    recipient_key::codec::decode(&envelope.payload)
        .map_err(|_| "recipient key tombstone dependency is not a recipient key".to_string())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{endpoint_shared, signed};
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::super::local_recipient_key;
    use super::super::super::recipient_key;
    use super::super::commands;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        codec::sign(
            [0; 32],
            private_key,
            vec![codec::TYPE_RECIPIENT_KEY_TOMBSTONE],
        )
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

    fn recipient_key_record(
        workspace_id: [u8; 32],
        signer_id: [u8; 32],
        signer_private_key: [u8; 32],
    ) -> Record {
        let local = local_recipient_key::commands::create(workspace_id)
            .expect("create local key")
            .value;
        recipient_key::commands::publish(recipient_key::commands::PublishRecipientKey {
            workspace_id,
            created_at_ms: 10,
            endpoint_shared_id: signer_id,
            signer_private_key,
            recipient_key: local.recipient_key,
        })
        .expect("publish")
        .events[0]
            .record()
            .clone()
    }

    fn tombstone_record(
        workspace_id: [u8; 32],
        signer_id: [u8; 32],
        signer_private_key: [u8; 32],
        old_id: [u8; 32],
        new_id: [u8; 32],
    ) -> Record {
        commands::tombstone(commands::TombstoneRecipientKey {
            workspace_id,
            created_at_ms: 12,
            endpoint_shared_id: signer_id,
            signer_private_key,
            old_recipient_key_id: old_id,
            new_recipient_key_id: new_id,
        })
        .expect("tombstone")
        .events[0]
            .record()
            .clone()
    }

    fn event_with_context<'a>(
        record: &'a Record,
        deps: Vec<([u8; 32], Record)>,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: deps
                    .into_iter()
                    .map(|(event_id, record)| DependencyContext { event_id, record })
                    .collect(),
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    #[test]
    fn projects_tombstone_row_for_authorized_endpoint_key_rotation() {
        let signer_private_key = [9; 32];
        let signer_record =
            endpoint_shared_record([1; 32], signing_public_key_for(&signer_private_key));
        let signer_id = event_id(&signer_record.canonical_bytes);
        let old_record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let old_id = event_id(&old_record.canonical_bytes);
        let new_record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let new_id = event_id(&new_record.canonical_bytes);
        let record = tombstone_record([1; 32], signer_id, signer_private_key, old_id, new_id);
        let event = event_with_context(
            &record,
            vec![
                (signer_id, signer_record),
                (old_id, old_record),
                (new_id, new_record),
            ],
        );

        let output = project(&event).expect("project tombstone");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.deletes.len(), 1);
        assert_eq!(output.rows[0].table, schema::RECIPIENT_KEY_TOMBSTONES);
        assert_eq!(
            output.deletes[0].table,
            recipient_key::schema::RECIPIENT_KEYS
        );
        let row =
            schema::decode_recipient_key_tombstone_row(&output.rows[0].key, &output.rows[0].value)
                .expect("decode row");
        assert_eq!(row.old_recipient_key_id, old_id);
        assert_eq!(row.new_recipient_key_id, new_id);
    }

    #[test]
    fn rejects_key_tombstone_for_another_endpoint() {
        let signer_private_key = [9; 32];
        let other_private_key = [7; 32];
        let signer_record =
            endpoint_shared_record([1; 32], signing_public_key_for(&signer_private_key));
        let signer_id = event_id(&signer_record.canonical_bytes);
        let other_record =
            endpoint_shared_record([1; 32], signing_public_key_for(&other_private_key));
        let other_id = event_id(&other_record.canonical_bytes);
        let old_record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let old_id = event_id(&old_record.canonical_bytes);
        let new_record = recipient_key_record([1; 32], other_id, other_private_key);
        let new_id = event_id(&new_record.canonical_bytes);
        let record = tombstone_record([1; 32], signer_id, signer_private_key, old_id, new_id);
        let event = event_with_context(
            &record,
            vec![
                (signer_id, signer_record),
                (old_id, old_record),
                (new_id, new_record),
            ],
        );

        assert_eq!(
            project(&event).expect_err("other endpoint key must fail"),
            "recipient key tombstone keys must belong to signer endpoint"
        );
    }
}
