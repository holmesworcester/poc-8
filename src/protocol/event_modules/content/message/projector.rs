//! Projector for signed messages.
//!
//! The content prepare step validates the signed envelope, checks authority,
//! and opens the ciphertext. This projector is intentionally pure row logic
//! over that prepared semantic fact plus labels loaded by the common pipeline.

use crate::protocol::event_modules::content::message_deletion::types::deletion_label_author;
use crate::protocol::event_modules::content::prepare::PreparedMessage;
use crate::protocol::event_modules::worker::{ProjectionOutput, TableDelete};

use super::schema;

pub fn project(prepared: &PreparedMessage, labels: &[Vec<u8>]) -> Result<ProjectionOutput, String> {
    let message = &prepared.plaintext;
    // Purge-on-project: a deletion event labels its target message id with
    // `content.deleted:<author_user_id>`. If the tombstone arrived first, the
    // message is valid but must not leave a visible row behind.
    let is_deleted_by_author = labels.iter().any(|label| {
        deletion_label_author(label)
            .map(|author| author == message.author_user_id)
            .unwrap_or(false)
    });
    if is_deleted_by_author {
        let key = schema::message_key(message.workspace_id, prepared.message_id);
        return Ok(ProjectionOutput {
            rows: vec![schema::message_tombstone_row(
                message.workspace_id,
                prepared.message_id,
                message.author_user_id,
            )],
            deletes: vec![TableDelete {
                table: schema::MESSAGES,
                key,
            }],
            labels: Vec::new(),
        });
    }

    Ok(ProjectionOutput::rows(vec![schema::message_row(
        prepared.message_id,
        prepared.signer_endpoint_shared_id,
        message,
    )?]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::event_modules::content::message::types::MessagePlaintext;
    use crate::protocol::event_modules::content::message_deletion::types::deletion_label;

    const WORKSPACE: [u8; 32] = [7; 32];
    const MESSAGE_ID: [u8; 32] = [8; 32];
    const AUTHOR: [u8; 32] = [9; 32];
    const SIGNER: [u8; 32] = [10; 32];

    fn prepared(text: &str) -> PreparedMessage {
        PreparedMessage {
            message_id: MESSAGE_ID,
            signer_endpoint_shared_id: SIGNER,
            plaintext: MessagePlaintext {
                workspace_id: WORKSPACE,
                created_at_ms: 5,
                author_user_id: AUTHOR,
                removal_frontier_id: [30; 32],
                local_key_secret_id: [31; 32],
                text: text.to_string(),
            },
        }
    }

    #[test]
    fn projects_plaintext_message_row() {
        let output = project(&prepared("hello"), &[]).expect("project message");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::MESSAGES);
        let row = schema::decode_message_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode message row");
        assert_eq!(row.workspace_id, WORKSPACE);
        assert_eq!(row.message_id, MESSAGE_ID);
        assert_eq!(row.author_user_id, AUTHOR);
        assert_eq!(row.signer_endpoint_shared_id, SIGNER);
        assert_eq!(row.text, "hello");
    }

    #[test]
    fn purges_message_on_project_when_self_deletion_label_is_present() {
        let output =
            project(&prepared("hello"), &[deletion_label(&AUTHOR)]).expect("project deleted");
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::MESSAGE_TOMBSTONES);
        assert!(output.labels.is_empty());
        assert_eq!(output.deletes.len(), 1);
        assert_eq!(output.deletes[0].table, schema::MESSAGES);
        assert_eq!(
            output.deletes[0].key,
            schema::message_key(WORKSPACE, MESSAGE_ID)
        );
    }

    #[test]
    fn ignores_deletion_label_authored_by_someone_other_than_message_author() {
        let output = project(&prepared("hello"), &[deletion_label(&[42; 32])])
            .expect("project not-by-author label");
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::MESSAGES);
        assert!(output.deletes.is_empty());
    }
}
