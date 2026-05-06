//! Projector for invite-secret events.
//!
//! Projection makes a bootstrap hash authorized by storing the corresponding
//! private value locally. The row is intentionally keyed by hash so a connection
//! request can prove knowledge without exposing the private value in the event.

use crate::core::store::TableRow;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::codec;
use super::schema;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let event = codec::decode(bytes)?;
    Ok(ProjectionOutput::rows(invite_secret(
        event.bootstrap_hash,
        event.bootstrap_secret,
        event.workspace_id,
        event.invite_event_id,
    )))
}

pub fn invite_secret(
    bootstrap_hash: [u8; 32],
    private_key: [u8; 32],
    workspace_id: Option<[u8; 32]>,
    invite_event_id: Option<[u8; 32]>,
) -> Vec<TableRow> {
    vec![TableRow {
        table: schema::INVITE_SECRETS,
        key: bootstrap_hash.to_vec(),
        value: schema::encode_invite_secret_row(private_key, workspace_id, invite_event_id),
    }]
}

#[cfg(test)]
mod tests {
    use super::super::types::InviteSecretEvent;
    use super::*;

    #[test]
    fn project_writes_secret_by_bootstrap_hash_as_local_authority_row() {
        let event = InviteSecretEvent::new([7; 32]);
        let output = project(&codec::encode(&event)).expect("project invite secret");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::INVITE_SECRETS);
        assert_eq!(output.rows[0].key, event.bootstrap_hash);
        assert_eq!(
            schema::decode_invite_secret_row(&output.rows[0].value)
                .expect("decode invite secret row"),
            schema::InviteSecretRow {
                bootstrap_secret: event.bootstrap_secret,
                workspace_id: None,
                invite_event_id: None,
            }
        );
    }
}
