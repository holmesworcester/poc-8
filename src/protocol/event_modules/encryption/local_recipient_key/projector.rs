//! Projector for local recipient key events.
//!
//! Projection writes private material only into the local table. Sync ignores
//! these event records because their scope is local. This projector does not
//! publish the public recipient-key fact or create key wraps; it only makes the
//! private half available to local workers.

use crate::protocol::event_modules::worker::ProjectionOutput;

use super::{codec, schema};

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let event = codec::decode(bytes)?;
    Ok(ProjectionOutput::rows(vec![
        schema::local_recipient_key_row(
            crate::protocol::event_modules::types::event_id(bytes),
            &event,
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::super::commands;
    use super::*;

    #[test]
    fn project_writes_private_material_by_workspace_and_event_id() {
        let event = commands::create([1; 32]).expect("create").value;
        let bytes = codec::encode(&event);
        let event_id = crate::protocol::event_modules::types::event_id(&bytes);
        let output = project(&bytes).expect("project local recipient key");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::LOCAL_RECIPIENT_KEYS);
        assert_eq!(
            output.rows[0].key,
            schema::local_recipient_key_key(event.workspace_id, event_id)
        );
        assert_eq!(
            schema::decode_local_recipient_key_row(&output.rows[0].key, &output.rows[0].value)
                .expect("decode row"),
            super::super::types::LocalRecipientKeyRow {
                workspace_id: event.workspace_id,
                local_recipient_key_id: event_id,
                recipient_key: event.recipient_key,
                recipient_secret: event.recipient_secret,
            }
        );
    }

    #[test]
    fn project_rejects_mismatched_key_material() {
        let good = commands::create([1; 32]).expect("create good").value;
        let bad = commands::create([1; 32]).expect("create bad").value;
        let bytes = codec::encode(&super::super::types::LocalRecipientKey {
            workspace_id: good.workspace_id,
            recipient_key: good.recipient_key,
            recipient_secret: bad.recipient_secret,
        });

        let err = project(&bytes).expect_err("mismatched keypair must fail");

        assert_eq!(err, "local recipient key secret does not match public key");
    }
}
