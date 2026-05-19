//! Projector for signed recipient key events.
//!
//! Projection validates that the signing endpoint membership belongs to the
//! same workspace and owns the signing public key named by the envelope. It
//! writes the public recipient-key row only; local private material and wrap
//! scheduling belong to sibling local event leaves and workers.

use crate::protocol::event_modules::identity::{endpoint_shared, signed};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let recipient_key = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(recipient_key.workspace_id) {
        return Err("recipient key workspace metadata does not match event body".to_string());
    }
    if envelope.signer_endpoint_shared_id != recipient_key.endpoint_shared_id {
        return Err("recipient key signer does not match payload endpoint".to_string());
    }

    let signer = event
        .context
        .dependency(&envelope.signer_endpoint_shared_id)
        .ok_or_else(|| "recipient key signer endpoint_shared dependency is missing".to_string())?;
    let signer_envelope = signed::codec::decode(&signer.canonical_bytes).map_err(|_| {
        "recipient key signer dependency is not a signed endpoint_shared".to_string()
    })?;
    if signer_envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err("recipient key signer dependency is not a signed endpoint_shared".to_string());
    }
    let signer_endpoint_shared =
        endpoint_shared::codec::decode(&signer_envelope.payload).map_err(|_| {
            "recipient key signer dependency is not a signed endpoint_shared".to_string()
        })?;
    if signer_endpoint_shared.workspace_id != recipient_key.workspace_id {
        return Err(
            "recipient key signer endpoint_shared workspace does not match event".to_string(),
        );
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err("recipient key signer public key does not match endpoint_shared".to_string());
    }
    if !signer_endpoint_shared.endpoint_role.can_receive_key_wraps() {
        return Err("recipient key signer endpoint role cannot receive key wraps".to_string());
    }

    Ok(ProjectionOutput::rows(vec![schema::recipient_key_row(
        event.context.event_id,
        &recipient_key,
    )?]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{endpoint_shared, signed};
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::commands;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        crate::core::crypto::ed25519_public_key(private_key)
    }

    fn endpoint_shared_record(workspace_id: [u8; 32], signing_public_key: [u8; 32]) -> Record {
        endpoint_shared_record_with_role(
            workspace_id,
            signing_public_key,
            crate::protocol::event_modules::identity::endpoint::types::EndpointRole::Device,
        )
    }

    fn endpoint_shared_record_with_role(
        workspace_id: [u8; 32],
        signing_public_key: [u8; 32],
        endpoint_role: crate::protocol::event_modules::identity::endpoint::types::EndpointRole,
    ) -> Record {
        let payload =
            endpoint_shared::codec::encode(&endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id: [3; 32],
                endpoint_id: [21; 32],
                signing_public_key,
                endpoint_role,
                device_name: "laptop".to_string(),
            })
            .expect("encode endpoint_shared");
        let signed = signed::commands::sign_payload([6; 32], &[5; 32], payload)
            .expect("sign endpoint_shared");
        signed.events[0].record().clone()
    }

    fn event_with_context<'a>(
        record: &'a Record,
        signer_id: [u8; 32],
        signer_record: Record,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: vec![DependencyContext {
                    event_id: signer_id,
                    record: signer_record,
                }],
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        }
    }

    fn recipient_key_record(
        workspace_id: [u8; 32],
        signer_id: [u8; 32],
        signer_private_key: [u8; 32],
    ) -> Record {
        let local = super::super::super::local_recipient_key::commands::create(workspace_id)
            .expect("create local key")
            .value;
        commands::publish(commands::PublishRecipientKey {
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

    #[test]
    fn projects_recipient_key_row_from_authorized_endpoint() {
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let signer_record = endpoint_shared_record([1; 32], signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let event = event_with_context(&record, signer_id, signer_record);

        let output = project(&event).expect("project recipient key");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::RECIPIENT_KEYS);
        let row = schema::decode_recipient_key_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, [1; 32]);
        assert_eq!(row.recipient_key_id, event.context.event_id);
        assert_eq!(row.endpoint_shared_id, signer_id);
    }

    #[test]
    fn rejects_missing_signer_dependency() {
        let signer_private_key = [9; 32];
        let signer_record =
            endpoint_shared_record([1; 32], signing_public_key_for(&signer_private_key));
        let signer_id = event_id(&signer_record.canonical_bytes);
        let record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: Vec::new(),
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        };

        assert_eq!(
            project(&event).expect_err("missing signer must fail"),
            "recipient key signer endpoint_shared dependency is missing"
        );
    }

    #[test]
    fn rejects_signer_public_key_or_workspace_mismatch() {
        let signer_private_key = [9; 32];
        let signer_record = endpoint_shared_record([1; 32], signing_public_key_for(&[8; 32]));
        let signer_id = event_id(&signer_record.canonical_bytes);
        let record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let event = event_with_context(&record, signer_id, signer_record);
        assert_eq!(
            project(&event).expect_err("wrong key must fail"),
            "recipient key signer public key does not match endpoint_shared"
        );

        let signer_record =
            endpoint_shared_record([2; 32], signing_public_key_for(&signer_private_key));
        let signer_id = event_id(&signer_record.canonical_bytes);
        let record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let event = event_with_context(&record, signer_id, signer_record);
        assert_eq!(
            project(&event).expect_err("wrong workspace must fail"),
            "recipient key signer endpoint_shared workspace does not match event"
        );
    }

    #[test]
    fn rejects_invite_server_endpoint_recipient_key() {
        let signer_private_key = [9; 32];
        let signer_record = endpoint_shared_record_with_role(
            [1; 32],
            signing_public_key_for(&signer_private_key),
            crate::protocol::event_modules::identity::endpoint::types::EndpointRole::InviteServer,
        );
        let signer_id = event_id(&signer_record.canonical_bytes);
        let record = recipient_key_record([1; 32], signer_id, signer_private_key);
        let event = event_with_context(&record, signer_id, signer_record);

        assert_eq!(
            project(&event).expect_err("invite-server recipient key must fail"),
            "recipient key signer endpoint role cannot receive key wraps"
        );
    }
}
