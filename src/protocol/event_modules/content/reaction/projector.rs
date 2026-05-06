//! Projector for signed reactions.
//!
//! The content prepare step validates the signer, author, target message, and
//! ciphertext. This projector only writes the prepared visible reaction row.

use crate::protocol::event_modules::content::prepare::PreparedReaction;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::schema;

pub fn project(prepared: &PreparedReaction) -> Result<ProjectionOutput, String> {
    Ok(ProjectionOutput::rows(vec![schema::reaction_row(
        prepared.reaction_id,
        prepared.signer_endpoint_shared_id,
        &prepared.plaintext,
    )?]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::event_modules::content::reaction::types::ReactionPlaintext;

    const WORKSPACE: [u8; 32] = [7; 32];
    const REACTION_ID: [u8; 32] = [8; 32];
    const TARGET: [u8; 32] = [9; 32];
    const AUTHOR: [u8; 32] = [10; 32];
    const SIGNER: [u8; 32] = [11; 32];

    fn prepared(emoji: &str) -> PreparedReaction {
        PreparedReaction {
            reaction_id: REACTION_ID,
            signer_endpoint_shared_id: SIGNER,
            plaintext: ReactionPlaintext {
                workspace_id: WORKSPACE,
                created_at_ms: 5,
                target_message_id: TARGET,
                author_user_id: AUTHOR,
                removal_frontier_id: [34; 32],
                local_key_secret_id: [35; 32],
                emoji: emoji.to_string(),
            },
        }
    }

    #[test]
    fn projects_one_reaction_row() {
        let output = project(&prepared("+1")).expect("project reaction");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::REACTIONS);
        let row = schema::decode_reaction_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode reaction row");
        assert_eq!(row.workspace_id, WORKSPACE);
        assert_eq!(row.reaction_id, REACTION_ID);
        assert_eq!(row.target_message_id, TARGET);
        assert_eq!(row.author_user_id, AUTHOR);
        assert_eq!(row.signer_endpoint_shared_id, SIGNER);
        assert_eq!(row.emoji, "+1");
    }
}
