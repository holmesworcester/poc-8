use super::super::ParsedEvent;
use super::codec::{
    kind_name, KIND_DEVICE_PUBKEY, KIND_HISTORY_DELETE, KIND_KEY_EPOCH, KIND_KEY_WRAP,
    KIND_KEY_WRAP_RECEIPT, KIND_MESSAGE_ENCRYPTED, KIND_RECIPIENT_CREATED, RECIPIENT_DEVICE,
    RECIPIENT_INVITE,
};
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

const ZERO_ID: [u8; 32] = [0; 32];

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS fs_events (
            workspace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            kind INTEGER NOT NULL,
            subject_id TEXT NOT NULL,
            aux_id_1 TEXT NOT NULL,
            aux_id_2 TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_fs_events_kind
            ON fs_events(workspace_id, kind);

        CREATE TABLE IF NOT EXISTS fs_recipients (
            workspace_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            recipient_kind INTEGER NOT NULL,
            created_event_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, recipient_id)
        );

        CREATE TABLE IF NOT EXISTS fs_pubkeys (
            workspace_id TEXT NOT NULL,
            pubkey_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            prev_pubkey_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, pubkey_id)
        );
        CREATE INDEX IF NOT EXISTS idx_fs_pubkeys_recipient
            ON fs_pubkeys(workspace_id, recipient_id);

        CREATE TABLE IF NOT EXISTS fs_pubkey_tombstones (
            workspace_id TEXT NOT NULL,
            pubkey_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            tombstone_event_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, pubkey_id, recipient_id)
        );

        CREATE TABLE IF NOT EXISTS fs_epochs (
            workspace_id TEXT NOT NULL,
            epoch_id TEXT NOT NULL,
            prev_epoch_id TEXT NOT NULL,
            removed_recipient_id TEXT NOT NULL,
            root_commitment BLOB NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, epoch_id)
        );

        CREATE TABLE IF NOT EXISTS fs_removed_recipients (
            workspace_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            epoch_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, recipient_id)
        );

        CREATE TABLE IF NOT EXISTS fs_key_wraps (
            workspace_id TEXT NOT NULL,
            wrap_id TEXT NOT NULL,
            epoch_id TEXT NOT NULL,
            pubkey_id TEXT NOT NULL,
            node_bit_len INTEGER NOT NULL,
            node_bytes BLOB NOT NULL,
            secret_commitment BLOB NOT NULL,
            ciphertext_commitment BLOB NOT NULL,
            PRIMARY KEY (workspace_id, wrap_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_fs_key_wraps_unique_target
            ON fs_key_wraps(workspace_id, epoch_id, pubkey_id, node_bit_len, node_bytes);

        CREATE TABLE IF NOT EXISTS fs_key_wrap_receipts (
            workspace_id TEXT NOT NULL,
            receipt_id TEXT NOT NULL,
            epoch_id TEXT NOT NULL,
            pubkey_id TEXT NOT NULL,
            node_bit_len INTEGER NOT NULL,
            node_bytes BLOB NOT NULL,
            wrap_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, receipt_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_fs_key_wrap_receipts_unique_target
            ON fs_key_wrap_receipts(workspace_id, epoch_id, pubkey_id, node_bit_len, node_bytes);

        CREATE TABLE IF NOT EXISTS fs_local_pubkey_purges (
            workspace_id TEXT NOT NULL,
            pubkey_id TEXT NOT NULL,
            purged_at_ms INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, pubkey_id)
        );

        CREATE TABLE IF NOT EXISTS fs_messages (
            workspace_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            epoch_id TEXT NOT NULL,
            unix_minute INTEGER NOT NULL,
            coord_event_id TEXT NOT NULL,
            ciphertext_commitment BLOB NOT NULL,
            PRIMARY KEY (workspace_id, message_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_fs_messages_coord
            ON fs_messages(workspace_id, epoch_id, unix_minute, coord_event_id);

        CREATE TABLE IF NOT EXISTS fs_history_deletes (
            workspace_id TEXT NOT NULL,
            delete_id TEXT NOT NULL,
            epoch_id TEXT NOT NULL,
            unix_minute INTEGER NOT NULL,
            coord_event_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, delete_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_fs_history_deletes_coord
            ON fs_history_deletes(workspace_id, epoch_id, unix_minute, coord_event_id);

        CREATE TABLE IF NOT EXISTS fs_local_epoch_roots (
            workspace_id TEXT NOT NULL,
            epoch_id TEXT NOT NULL,
            root_secret BLOB NOT NULL,
            PRIMARY KEY (workspace_id, epoch_id)
        );

        CREATE TABLE IF NOT EXISTS fs_local_private_keys (
            workspace_id TEXT NOT NULL,
            pubkey_id TEXT NOT NULL,
            private_key BLOB NOT NULL,
            PRIMARY KEY (workspace_id, pubkey_id)
        );

        CREATE TABLE IF NOT EXISTS fs_local_unwrapped_nodes (
            workspace_id TEXT NOT NULL,
            pubkey_id TEXT NOT NULL,
            epoch_id TEXT NOT NULL,
            node_bit_len INTEGER NOT NULL,
            node_bytes BLOB NOT NULL,
            PRIMARY KEY (workspace_id, pubkey_id, epoch_id, node_bit_len, node_bytes)
        );
        ",
    )?;
    Ok(())
}

pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let event = match parsed {
        ParsedEvent::ForwardSecret(event) => event,
        _ => return ProjectorResult::reject("not a forward_secret event".to_string()),
    };

    if let Some(types) = ctx.labels.get(event_id_b64) {
        for t in types {
            if t == "deleted" || t.starts_with("removed_by:") || t == "superseded" {
                return ProjectorResult::reject(format!("forward_secret gated by label `{}`", t));
            }
        }
    }

    if !matches!(
        event.kind,
        KIND_RECIPIENT_CREATED
            | KIND_DEVICE_PUBKEY
            | KIND_KEY_EPOCH
            | KIND_KEY_WRAP
            | KIND_KEY_WRAP_RECEIPT
            | KIND_MESSAGE_ENCRYPTED
            | KIND_HISTORY_DELETE
    ) {
        return ProjectorResult::reject(format!("unknown forward_secret kind {}", event.kind));
    }
    if event.scalar_2 > 256 {
        return ProjectorResult::reject("node_bit_len must be <= 256".to_string());
    }
    if event.kind == KIND_RECIPIENT_CREATED
        && !matches!(event.small_1, RECIPIENT_DEVICE | RECIPIENT_INVITE)
    {
        return ProjectorResult::reject("invalid forward_secret recipient kind".to_string());
    }

    let ws = event_id_to_base64(&event.workspace_id);
    let subject = event_id_to_base64(&event.subject_id);
    let aux1 = event_id_to_base64(&event.aux_id_1);
    let aux2 = event_id_to_base64(&event.aux_id_2);
    let coord = event_id_to_base64(&event.coord_event_id);
    let mut ops = vec![WriteOp::InsertOrIgnore {
        table: "fs_events",
        columns: vec![
            "workspace_id",
            "event_id",
            "kind",
            "subject_id",
            "aux_id_1",
            "aux_id_2",
            "created_at_ms",
        ],
        values: vec![
            SqlVal::Text(ws.clone()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Int(event.kind as i64),
            SqlVal::Text(subject.clone()),
            SqlVal::Text(aux1.clone()),
            SqlVal::Text(aux2.clone()),
            SqlVal::Int(event.created_at_ms as i64),
        ],
    }];

    match event.kind {
        KIND_RECIPIENT_CREATED => {
            ops.push(WriteOp::InsertOrIgnore {
                table: "fs_recipients",
                columns: vec![
                    "workspace_id",
                    "recipient_id",
                    "recipient_kind",
                    "created_event_id",
                ],
                values: vec![
                    SqlVal::Text(ws),
                    SqlVal::Text(subject),
                    SqlVal::Int(event.small_1 as i64),
                    SqlVal::Text(event_id_b64.to_string()),
                ],
            });
        }
        KIND_DEVICE_PUBKEY => {
            ops.push(WriteOp::InsertOrIgnore {
                table: "fs_pubkeys",
                columns: vec![
                    "workspace_id",
                    "pubkey_id",
                    "recipient_id",
                    "prev_pubkey_id",
                    "public_key",
                    "created_at_ms",
                ],
                values: vec![
                    SqlVal::Text(ws.clone()),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(subject.clone()),
                    SqlVal::Text(aux1.clone()),
                    SqlVal::Blob(event.data_1.to_vec()),
                    SqlVal::Int(event.created_at_ms as i64),
                ],
            });
            if event.aux_id_1 != ZERO_ID {
                ops.push(WriteOp::InsertOrIgnore {
                    table: "fs_pubkey_tombstones",
                    columns: vec![
                        "workspace_id",
                        "pubkey_id",
                        "recipient_id",
                        "tombstone_event_id",
                    ],
                    values: vec![
                        SqlVal::Text(ws),
                        SqlVal::Text(aux1),
                        SqlVal::Text(subject),
                        SqlVal::Text(event_id_b64.to_string()),
                    ],
                });
            }
        }
        KIND_KEY_EPOCH => {
            ops.push(WriteOp::InsertOrIgnore {
                table: "fs_epochs",
                columns: vec![
                    "workspace_id",
                    "epoch_id",
                    "prev_epoch_id",
                    "removed_recipient_id",
                    "root_commitment",
                    "created_at_ms",
                ],
                values: vec![
                    SqlVal::Text(ws.clone()),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(aux1),
                    SqlVal::Text(aux2.clone()),
                    SqlVal::Blob(event.data_1.to_vec()),
                    SqlVal::Int(event.created_at_ms as i64),
                ],
            });
            if event.aux_id_2 != ZERO_ID {
                ops.push(WriteOp::InsertOrIgnore {
                    table: "fs_removed_recipients",
                    columns: vec!["workspace_id", "recipient_id", "epoch_id"],
                    values: vec![
                        SqlVal::Text(ws),
                        SqlVal::Text(aux2),
                        SqlVal::Text(event_id_b64.to_string()),
                    ],
                });
            }
        }
        KIND_KEY_WRAP => {
            ops.push(WriteOp::InsertOrIgnore {
                table: "fs_key_wraps",
                columns: vec![
                    "workspace_id",
                    "wrap_id",
                    "epoch_id",
                    "pubkey_id",
                    "node_bit_len",
                    "node_bytes",
                    "secret_commitment",
                    "ciphertext_commitment",
                ],
                values: vec![
                    SqlVal::Text(ws),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(subject),
                    SqlVal::Text(aux1),
                    SqlVal::Int(event.scalar_2 as i64),
                    SqlVal::Blob(event.node_bytes.to_vec()),
                    SqlVal::Blob(event.data_1.to_vec()),
                    SqlVal::Blob(event.data_2.to_vec()),
                ],
            });
        }
        KIND_KEY_WRAP_RECEIPT => {
            ops.push(WriteOp::InsertOrIgnore {
                table: "fs_key_wrap_receipts",
                columns: vec![
                    "workspace_id",
                    "receipt_id",
                    "epoch_id",
                    "pubkey_id",
                    "node_bit_len",
                    "node_bytes",
                    "wrap_id",
                ],
                values: vec![
                    SqlVal::Text(ws),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(subject),
                    SqlVal::Text(aux1),
                    SqlVal::Int(event.scalar_2 as i64),
                    SqlVal::Blob(event.node_bytes.to_vec()),
                    SqlVal::Text(aux2),
                ],
            });
        }
        KIND_MESSAGE_ENCRYPTED => {
            ops.push(WriteOp::InsertOrIgnore {
                table: "fs_messages",
                columns: vec![
                    "workspace_id",
                    "message_id",
                    "epoch_id",
                    "unix_minute",
                    "coord_event_id",
                    "ciphertext_commitment",
                ],
                values: vec![
                    SqlVal::Text(ws),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(subject),
                    SqlVal::Int(event.scalar_1 as i64),
                    SqlVal::Text(coord),
                    SqlVal::Blob(event.data_1.to_vec()),
                ],
            });
        }
        KIND_HISTORY_DELETE => {
            ops.push(WriteOp::InsertOrIgnore {
                table: "fs_history_deletes",
                columns: vec![
                    "workspace_id",
                    "delete_id",
                    "epoch_id",
                    "unix_minute",
                    "coord_event_id",
                ],
                values: vec![
                    SqlVal::Text(ws.clone()),
                    SqlVal::Text(event_id_b64.to_string()),
                    SqlVal::Text(subject.clone()),
                    SqlVal::Int(event.scalar_1 as i64),
                    SqlVal::Text(coord),
                ],
            });
            ops.push(WriteOp::Delete {
                table: "fs_local_epoch_roots",
                where_clause: vec![
                    ("workspace_id", SqlVal::Text(ws)),
                    ("epoch_id", SqlVal::Text(subject)),
                ],
            });
        }
        _ => unreachable!("kind already validated: {}", kind_name(event.kind)),
    }

    ProjectorResult::valid(ops)
}
