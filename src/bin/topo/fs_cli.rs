use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use clap::Subcommand;
use rand::rngs::OsRng;
use rusqlite::{params, OptionalExtension};
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

use topo::crypto::{event_id_from_base64, event_id_from_hex, event_id_to_base64, EventId};
use topo::event_modules::forward_secret::{ForwardSecretEvent, RECIPIENT_DEVICE, RECIPIENT_INVITE};
use topo::event_modules::ParsedEvent;
use topo::local_intents::{emit_local_event, wait_for_terminal};
use topo::state::db::{ensure_infra_schema, open_connection};
use topo::state::events_canonical::{EventScope, EventStatus};

const POLL_DEADLINE: Duration = Duration::from_secs(120);
const ZERO_ID: EventId = [0; 32];
const ROOT_NODE: EventId = [0; 32];
const ROOT_NODE_BITS: u32 = 0;
const AES_GCM_NONCE_BYTES: usize = 12;
const AES_GCM_TAG_BYTES: usize = 16;
const X25519_PUBLIC_BYTES: usize = 32;

#[derive(Subcommand, Debug)]
pub enum FsCommand {
    /// Create a forward-secret recipient fact.
    Recipient {
        /// Stable local label used to derive the recipient id.
        label: String,
        /// Model this recipient as a one-use invite key instead of a device.
        #[arg(long)]
        invite: bool,
    },

    /// Publish a device pubkey; --prev tombstones the earlier pubkey.
    Pubkey {
        /// Hex or base64 recipient id from `fs recipient`.
        recipient_id: String,
        /// Hex-encoded 32-byte X25519 private key.
        private_key: String,
        /// Previous pubkey id to tombstone.
        #[arg(long)]
        prev: Option<String>,
    },

    /// Create a key epoch and retain its root locally.
    Epoch {
        /// Hex-encoded 32-byte epoch root secret.
        root_secret: String,
        /// Previous epoch id, if this rotates an existing epoch.
        #[arg(long)]
        prev: Option<String>,
        /// Recipient id removed by this epoch frontier.
        #[arg(long = "remove-recipient")]
        remove_recipient: Option<String>,
    },

    /// Create an encrypted-message coordinate under an epoch.
    Message {
        /// Hex or base64 epoch id from `fs epoch`.
        epoch_id: String,
        /// Stable coordinate label and plaintext for this test message.
        label: String,
    },

    /// Delete a history coordinate and puncture the local epoch root.
    Delete {
        /// Hex or base64 epoch id.
        epoch_id: String,
        /// Hex or base64 coordinate event id from `fs message`.
        coord_event_id: String,
        /// Unix minute from `fs message`.
        unix_minute: u64,
    },

    /// Install local private key material for a pubkey label.
    #[command(name = "private-key")]
    PrivateKey {
        /// Hex or base64 pubkey id from `fs pubkey`.
        pubkey_id: String,
        /// Hex-encoded 32-byte X25519 private key.
        private_key: String,
    },

    /// Generate a fresh X25519 private/public key pair for tests or manual use.
    Keygen,

    /// Run bounded deterministic wrap/receipt/local-purge maintenance.
    Expand,

    /// Show forward-secret pubkeys and local material status.
    Keys,

    /// Show deterministic key wraps and receipt status.
    Wraps,

    /// Check whether a message coordinate is recoverable from live local key material.
    Recoverable {
        /// Hex or base64 epoch id.
        epoch_id: String,
        /// Hex or base64 coordinate event id from `fs message`.
        coord_event_id: String,
        /// Unix minute from `fs message`.
        unix_minute: u64,
    },
}

pub async fn run(
    db_path: &Path,
    command: FsCommand,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match command {
        FsCommand::Recipient { label, invite } => cmd_recipient(db_path, &label, invite).await,
        FsCommand::Pubkey {
            recipient_id,
            private_key,
            prev,
        } => cmd_pubkey(db_path, &recipient_id, &private_key, prev.as_deref()).await,
        FsCommand::Epoch {
            root_secret,
            prev,
            remove_recipient,
        } => {
            cmd_epoch(
                db_path,
                &root_secret,
                prev.as_deref(),
                remove_recipient.as_deref(),
            )
            .await
        }
        FsCommand::Message { epoch_id, label } => cmd_message(db_path, &epoch_id, &label).await,
        FsCommand::Delete {
            epoch_id,
            coord_event_id,
            unix_minute,
        } => cmd_delete(db_path, &epoch_id, &coord_event_id, unix_minute).await,
        FsCommand::PrivateKey {
            pubkey_id,
            private_key,
        } => cmd_private_key(db_path, &pubkey_id, &private_key),
        FsCommand::Keygen => cmd_keygen(),
        FsCommand::Expand => cmd_expand(db_path).await,
        FsCommand::Keys => cmd_keys(db_path),
        FsCommand::Wraps => cmd_wraps(db_path),
        FsCommand::Recoverable {
            epoch_id,
            coord_event_id,
            unix_minute,
        } => cmd_recoverable(db_path, &epoch_id, &coord_event_id, unix_minute),
    }
}

async fn cmd_recipient(
    db_path: &Path,
    label: &str,
    invite: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workspace_id = current_workspace(db_path)?;
    let kind = if invite {
        RECIPIENT_INVITE
    } else {
        RECIPIENT_DEVICE
    };
    let recipient_id = hash_parts(&[
        b"fs-recipient-id-v1",
        &workspace_id,
        label.as_bytes(),
        &[kind],
    ]);
    let event = ParsedEvent::ForwardSecret(ForwardSecretEvent::recipient_created(
        now_ms() as u64,
        workspace_id,
        recipient_id,
        kind,
    ));
    let emitted = emit_fs_event_and_wait(db_path, "fs_recipient", event, workspace_id).await?;
    println!(
        "recipient_id={} recipient_kind={} event_id={}",
        hex_id(&recipient_id),
        if invite { "invite" } else { "device" },
        hex_id(&emitted)
    );
    Ok(())
}

async fn cmd_pubkey(
    db_path: &Path,
    recipient_id: &str,
    private_key_hex: &str,
    prev: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workspace_id = current_workspace(db_path)?;
    let recipient_id = parse_id(recipient_id, "recipient_id")?;
    let prev_pubkey_id = match prev {
        Some(prev) => parse_id(prev, "prev")?,
        None => ZERO_ID,
    };
    let private_key = parse_private_key_hex(private_key_hex)?;
    let public_key = public_key_for_private(&private_key);
    let event = ParsedEvent::ForwardSecret(ForwardSecretEvent::device_pubkey(
        now_ms() as u64,
        workspace_id,
        recipient_id,
        prev_pubkey_id,
        public_key,
    ));
    let emitted = emit_fs_event_and_wait(db_path, "fs_pubkey", event, workspace_id).await?;
    println!(
        "pubkey_id={} recipient_id={} public_key={} prev_pubkey_id={}",
        hex_id(&emitted),
        hex_id(&recipient_id),
        hex_id(&public_key),
        hex_id(&prev_pubkey_id)
    );
    Ok(())
}

async fn cmd_epoch(
    db_path: &Path,
    root_secret_hex: &str,
    prev: Option<&str>,
    remove_recipient: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workspace_id = current_workspace(db_path)?;
    let prev_epoch_id = match prev {
        Some(prev) => parse_id(prev, "prev")?,
        None => ZERO_ID,
    };
    let removed_recipient_id = match remove_recipient {
        Some(recipient) => parse_id(recipient, "remove-recipient")?,
        None => ZERO_ID,
    };
    let root_secret = parse_private_key_hex(root_secret_hex)?;
    let event = ParsedEvent::ForwardSecret(ForwardSecretEvent::key_epoch(
        now_ms() as u64,
        workspace_id,
        prev_epoch_id,
        removed_recipient_id,
        root_commitment(&root_secret),
    ));
    let epoch_id = emit_fs_event_and_wait(db_path, "fs_epoch", event, workspace_id).await?;

    let conn = open_ready_connection(db_path)?;
    conn.execute(
        "INSERT OR IGNORE INTO fs_local_epoch_roots
            (workspace_id, epoch_id, root_secret)
         VALUES (?1, ?2, ?3)",
        params![
            id_b64(&workspace_id),
            id_b64(&epoch_id),
            root_secret.to_vec()
        ],
    )?;
    println!(
        "epoch_id={} prev_epoch_id={} removed_recipient_id={} local_root=present",
        hex_id(&epoch_id),
        hex_id(&prev_epoch_id),
        hex_id(&removed_recipient_id)
    );
    Ok(())
}

async fn cmd_message(
    db_path: &Path,
    epoch_id: &str,
    label: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workspace_id = current_workspace(db_path)?;
    let epoch_id = parse_id(epoch_id, "epoch_id")?;
    let unix_minute = (now_ms() as u64) / 60_000;
    let coord_event_id = hash_parts(&[
        b"fs-message-coord-v1",
        &workspace_id,
        &epoch_id,
        label.as_bytes(),
    ]);
    let conn = open_ready_connection(db_path)?;
    let root_secret = local_epoch_root(&conn, &id_b64(&workspace_id), &id_b64(&epoch_id))?
        .ok_or_else(|| format!("missing local root for epoch {}", hex_id(&epoch_id)))?;
    let leaf = history_leaf(&epoch_id, unix_minute, &coord_event_id);
    let message_key = message_key(&root_secret, &leaf);
    let nonce = deterministic_nonce(
        b"fs-message-nonce-v1",
        &[&epoch_id, &unix_minute.to_le_bytes(), &coord_event_id],
    );
    let ciphertext = encrypt_aes_gcm(&message_key, &nonce, label.as_bytes())?;
    let payload = pack_nonce_ciphertext(&nonce, &ciphertext);
    let ciphertext_hash = hash_parts(&[b"fs-message-ciphertext-hash-v1", &payload]);
    let event = ParsedEvent::ForwardSecret(ForwardSecretEvent::message_encrypted(
        now_ms() as u64,
        workspace_id,
        epoch_id,
        unix_minute,
        coord_event_id,
        ciphertext_hash,
        payload,
    ));
    let message_id = emit_fs_event_and_wait(db_path, "fs_message", event, workspace_id).await?;
    println!(
        "message_id={} epoch_id={} coord_event_id={} unix_minute={}",
        hex_id(&message_id),
        hex_id(&epoch_id),
        hex_id(&coord_event_id),
        unix_minute
    );
    Ok(())
}

async fn cmd_delete(
    db_path: &Path,
    epoch_id: &str,
    coord_event_id: &str,
    unix_minute: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workspace_id = current_workspace(db_path)?;
    let epoch_id = parse_id(epoch_id, "epoch_id")?;
    let coord_event_id = parse_id(coord_event_id, "coord_event_id")?;
    let event = ParsedEvent::ForwardSecret(ForwardSecretEvent::history_delete(
        now_ms() as u64,
        workspace_id,
        epoch_id,
        unix_minute,
        coord_event_id,
    ));
    let delete_id = emit_fs_event_and_wait(db_path, "fs_delete", event, workspace_id).await?;
    println!(
        "delete_id={} epoch_id={} coord_event_id={} unix_minute={}",
        hex_id(&delete_id),
        hex_id(&epoch_id),
        hex_id(&coord_event_id),
        unix_minute
    );
    Ok(())
}

fn cmd_private_key(
    db_path: &Path,
    pubkey_id: &str,
    private_key_hex: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workspace_id = current_workspace(db_path)?;
    let ws = id_b64(&workspace_id);
    let pubkey_id = parse_id(pubkey_id, "pubkey_id")?;
    let pubkey = id_b64(&pubkey_id);
    let private_key = parse_private_key_hex(private_key_hex)?;
    let public_key = public_key_for_private(&private_key);
    let conn = open_ready_connection(db_path)?;

    if is_locally_purged(&conn, &ws, &pubkey)? {
        println!(
            "pubkey_id={} local_material=purged skipped=true",
            hex_id(&pubkey_id)
        );
        return Ok(());
    }

    let expected: Option<Vec<u8>> = conn
        .query_row(
            "SELECT public_key FROM fs_pubkeys
             WHERE workspace_id = ?1 AND pubkey_id = ?2",
            params![&ws, &pubkey],
            |r| r.get(0),
        )
        .optional()?;
    let Some(expected) = expected else {
        return Err(format!("unknown pubkey_id {}", hex_id(&pubkey_id)).into());
    };
    if expected.as_slice() != public_key {
        return Err(format!(
            "private key does not match pubkey_id {}",
            hex_id(&pubkey_id)
        )
        .into());
    }

    conn.execute(
        "INSERT OR REPLACE INTO fs_local_private_keys
            (workspace_id, pubkey_id, private_key)
         VALUES (?1, ?2, ?3)",
        params![&ws, &pubkey, private_key.to_vec()],
    )?;
    let unwrapped = materialize_unwrapped_nodes(&conn, &ws, &pubkey, &private_key)?;
    println!(
        "pubkey_id={} local_material=present unwrapped_nodes={}",
        hex_id(&pubkey_id),
        unwrapped
    );
    Ok(())
}

fn cmd_keygen() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let private_key = secret.to_bytes();
    let public_key = PublicKey::from(&secret).to_bytes();
    println!(
        "private_key={} public_key={}",
        hex::encode(private_key),
        hex::encode(public_key)
    );
    Ok(())
}

async fn cmd_expand(db_path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workspace_id = current_workspace(db_path)?;
    let ws = id_b64(&workspace_id);
    let mut emitted_wraps = 0usize;
    let mut emitted_receipts = 0usize;
    let mut purged_pubkeys = 0usize;

    for _ in 0..4 {
        let wrap_jobs = {
            let conn = open_ready_connection(db_path)?;
            wrap_jobs(&conn, &ws)?
        };
        if wrap_jobs.is_empty() {
            break;
        }
        for job in wrap_jobs {
            let payload = encrypt_wrap_payload(
                &job.root_secret,
                &job.pubkey_id,
                &job.public_key,
                &ROOT_NODE,
                ROOT_NODE_BITS,
            )?;
            let ciphertext_hash = hash_parts(&[b"fs-wrap-ciphertext-hash-v1", &payload]);
            let event = ParsedEvent::ForwardSecret(ForwardSecretEvent::key_wrap(
                0,
                workspace_id,
                job.epoch_id,
                job.pubkey_id,
                ROOT_NODE,
                ROOT_NODE_BITS,
                secret_commitment(&job.root_secret, &ROOT_NODE, ROOT_NODE_BITS),
                ciphertext_hash,
                payload,
            ));
            let _ = emit_fs_event_and_wait(db_path, "fs_key_wrap", event, workspace_id).await?;
            emitted_wraps += 1;
        }
    }

    {
        let conn = open_ready_connection(db_path)?;
        let keys = local_private_keys(&conn, &ws)?;
        for (pubkey, private_key) in keys {
            let _ = materialize_unwrapped_nodes(&conn, &ws, &pubkey, &private_key)?;
        }
    }

    for _ in 0..4 {
        let receipt_jobs = {
            let conn = open_ready_connection(db_path)?;
            receipt_jobs(&conn, &ws)?
        };
        if receipt_jobs.is_empty() {
            break;
        }
        for job in receipt_jobs {
            let event = ParsedEvent::ForwardSecret(ForwardSecretEvent::key_wrap_receipt(
                0,
                workspace_id,
                job.epoch_id,
                job.pubkey_id,
                job.wrap_id,
                job.node_bytes,
                job.node_bit_len,
            ));
            let _ =
                emit_fs_event_and_wait(db_path, "fs_key_wrap_receipt", event, workspace_id).await?;
            emitted_receipts += 1;
        }
    }

    {
        let conn = open_ready_connection(db_path)?;
        for pubkey in purge_ready_pubkeys(&conn, &ws)? {
            conn.execute(
                "DELETE FROM fs_local_private_keys
                 WHERE workspace_id = ?1 AND pubkey_id = ?2",
                params![&ws, &pubkey],
            )?;
            conn.execute(
                "DELETE FROM fs_local_unwrapped_nodes
                 WHERE workspace_id = ?1 AND pubkey_id = ?2",
                params![&ws, &pubkey],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO fs_local_pubkey_purges
                    (workspace_id, pubkey_id, purged_at_ms)
                 VALUES (?1, ?2, ?3)",
                params![&ws, &pubkey, now_ms()],
            )?;
            println!("purged_pubkey_id={}", hex_from_b64(&pubkey)?);
            purged_pubkeys += 1;
        }
    }

    println!(
        "expand emitted_wraps={} emitted_receipts={} purged_pubkeys={}",
        emitted_wraps, emitted_receipts, purged_pubkeys
    );
    Ok(())
}

fn cmd_keys(db_path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workspace_id = current_workspace(db_path)?;
    let ws = id_b64(&workspace_id);
    let conn = open_ready_connection(db_path)?;
    let mut stmt = conn.prepare(
        "SELECT p.pubkey_id, p.recipient_id,
                EXISTS(SELECT 1 FROM fs_pubkey_tombstones t
                       WHERE t.workspace_id = p.workspace_id
                         AND t.pubkey_id = p.pubkey_id),
                EXISTS(SELECT 1 FROM fs_removed_recipients r
                       WHERE r.workspace_id = p.workspace_id
                         AND r.recipient_id = p.recipient_id),
                EXISTS(SELECT 1 FROM fs_local_private_keys lk
                       WHERE lk.workspace_id = p.workspace_id
                         AND lk.pubkey_id = p.pubkey_id),
                EXISTS(SELECT 1 FROM fs_local_unwrapped_nodes n
                       WHERE n.workspace_id = p.workspace_id
                         AND n.pubkey_id = p.pubkey_id),
                EXISTS(SELECT 1 FROM fs_local_pubkey_purges lp
                       WHERE lp.workspace_id = p.workspace_id
                         AND lp.pubkey_id = p.pubkey_id)
         FROM fs_pubkeys p
         WHERE p.workspace_id = ?1
         ORDER BY p.created_at_ms ASC, p.pubkey_id ASC",
    )?;
    let rows = stmt
        .query_map(params![&ws], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, bool>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, bool>(4)?,
                r.get::<_, bool>(5)?,
                r.get::<_, bool>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        println!("(no fs pubkeys)");
        return Ok(());
    }
    for (pubkey, recipient, tombstoned, removed, private_present, unwrapped, purged) in rows {
        let status = if removed {
            "removed"
        } else if tombstoned {
            "tombstoned"
        } else {
            "active"
        };
        let local_material = if purged {
            "purged"
        } else if private_present || unwrapped {
            "present"
        } else {
            "absent"
        };
        println!(
            "pubkey_id={} recipient_id={} status={} local_material={}",
            hex_from_b64(&pubkey)?,
            hex_from_b64(&recipient)?,
            status,
            local_material
        );
    }
    Ok(())
}

fn cmd_wraps(db_path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workspace_id = current_workspace(db_path)?;
    let ws = id_b64(&workspace_id);
    let conn = open_ready_connection(db_path)?;
    let mut stmt = conn.prepare(
        "SELECT w.wrap_id, w.epoch_id, w.pubkey_id, w.node_bit_len,
                EXISTS(SELECT 1 FROM fs_key_wrap_receipts r
                       WHERE r.workspace_id = w.workspace_id
                         AND r.epoch_id = w.epoch_id
                         AND r.pubkey_id = w.pubkey_id
                         AND r.node_bit_len = w.node_bit_len
                         AND r.node_bytes = w.node_bytes)
         FROM fs_key_wraps w
         WHERE w.workspace_id = ?1
         ORDER BY w.epoch_id ASC, w.pubkey_id ASC",
    )?;
    let rows = stmt
        .query_map(params![&ws], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, bool>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        println!("(no fs wraps)");
        return Ok(());
    }
    for (wrap, epoch, pubkey, node_bit_len, receipted) in rows {
        println!(
            "wrap_id={} epoch_id={} pubkey_id={} node_bit_len={} receipted={}",
            hex_from_b64(&wrap)?,
            hex_from_b64(&epoch)?,
            hex_from_b64(&pubkey)?,
            node_bit_len,
            if receipted { "yes" } else { "no" }
        );
    }
    Ok(())
}

fn cmd_recoverable(
    db_path: &Path,
    epoch_id: &str,
    coord_event_id: &str,
    unix_minute: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workspace_id = current_workspace(db_path)?;
    let ws = id_b64(&workspace_id);
    let epoch_id = parse_id(epoch_id, "epoch_id")?;
    let coord_event_id = parse_id(coord_event_id, "coord_event_id")?;
    let epoch = id_b64(&epoch_id);
    let coord = id_b64(&coord_event_id);
    let conn = open_ready_connection(db_path)?;
    let message_payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT ciphertext FROM fs_messages
         WHERE workspace_id = ?1
           AND epoch_id = ?2
           AND unix_minute = ?3
           AND coord_event_id = ?4",
            params![&ws, &epoch, unix_minute as i64, &coord],
            |r| r.get(0),
        )
        .optional()?;
    let leaf = history_leaf(&epoch_id, unix_minute, &coord_event_id);
    let mut local_root_decrypts = false;
    if let Some(payload) = message_payload.as_deref() {
        if let Some(root_secret) = local_epoch_root(&conn, &ws, &epoch)? {
            local_root_decrypts = decrypt_message_payload(&root_secret, &leaf, payload).is_ok();
        }
    }
    let mut unwrapped_node_decrypts = false;
    let mut stmt = conn.prepare(
        "SELECT node_bytes, node_bit_len, node_secret FROM fs_local_unwrapped_nodes
         WHERE workspace_id = ?1 AND epoch_id = ?2",
    )?;
    let mut rows = stmt.query(params![&ws, &epoch])?;
    while let Some(row) = rows.next()? {
        let node_bytes: Vec<u8> = row.get(0)?;
        let node_bit_len: u32 = row.get::<_, i64>(1)? as u32;
        let node_secret = vec_to_id(row.get::<_, Vec<u8>>(2)?, "node_secret")?;
        if message_payload.as_deref().is_some_and(|payload| {
            prefix_contains(&node_bytes, node_bit_len, &leaf)
                && decrypt_message_payload(&node_secret, &leaf, payload).is_ok()
        }) {
            unwrapped_node_decrypts = true;
            break;
        }
    }
    let message_known = message_payload.is_some();
    let recoverable = local_root_decrypts || unwrapped_node_decrypts;
    println!(
        "recoverable={} message_known={} local_root={} unwrapped_node={}",
        if recoverable { "yes" } else { "no" },
        if message_known { "yes" } else { "no" },
        if local_root_decrypts { "yes" } else { "no" },
        if unwrapped_node_decrypts { "yes" } else { "no" }
    );
    Ok(())
}

#[derive(Debug)]
struct WrapJob {
    epoch_id: EventId,
    pubkey_id: EventId,
    public_key: EventId,
    root_secret: EventId,
}

#[derive(Debug)]
struct ReceiptJob {
    epoch_id: EventId,
    pubkey_id: EventId,
    wrap_id: EventId,
    node_bytes: EventId,
    node_bit_len: u32,
}

fn wrap_jobs(
    conn: &rusqlite::Connection,
    ws: &str,
) -> Result<Vec<WrapJob>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT r.epoch_id, r.root_secret, p.pubkey_id, p.public_key
         FROM fs_local_epoch_roots r
         JOIN fs_pubkeys p ON p.workspace_id = r.workspace_id
         WHERE r.workspace_id = ?1
           AND NOT EXISTS(SELECT 1 FROM fs_pubkey_tombstones t
                          WHERE t.workspace_id = p.workspace_id
                            AND t.pubkey_id = p.pubkey_id)
           AND NOT EXISTS(SELECT 1 FROM fs_removed_recipients rr
                          WHERE rr.workspace_id = p.workspace_id
                            AND rr.recipient_id = p.recipient_id)
           AND NOT EXISTS(SELECT 1 FROM fs_local_pubkey_purges lp
                          WHERE lp.workspace_id = p.workspace_id
                            AND lp.pubkey_id = p.pubkey_id)
           AND NOT EXISTS(SELECT 1 FROM fs_key_wraps w
                          WHERE w.workspace_id = r.workspace_id
                            AND w.epoch_id = r.epoch_id
                            AND w.pubkey_id = p.pubkey_id
                            AND w.node_bit_len = ?2
                            AND w.node_bytes = ?3)
         ORDER BY r.epoch_id ASC, p.pubkey_id ASC",
    )?;
    let rows = stmt
        .query_map(
            params![ws, ROOT_NODE_BITS as i64, ROOT_NODE.to_vec()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::new();
    for (epoch, root_secret, pubkey, public_key) in rows {
        out.push(WrapJob {
            epoch_id: b64_to_id(&epoch)?,
            root_secret: vec_to_id(root_secret, "root_secret")?,
            pubkey_id: b64_to_id(&pubkey)?,
            public_key: vec_to_id(public_key, "public_key")?,
        });
    }
    Ok(out)
}

fn receipt_jobs(
    conn: &rusqlite::Connection,
    ws: &str,
) -> Result<Vec<ReceiptJob>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT w.wrap_id, w.epoch_id, w.pubkey_id, w.node_bytes, w.node_bit_len, w.ciphertext,
                p.public_key, lk.private_key
         FROM fs_key_wraps w
         JOIN fs_pubkeys p
           ON p.workspace_id = w.workspace_id
          AND p.pubkey_id = w.pubkey_id
         JOIN fs_local_private_keys lk
           ON lk.workspace_id = w.workspace_id
          AND lk.pubkey_id = w.pubkey_id
         WHERE w.workspace_id = ?1
           AND NOT EXISTS(SELECT 1 FROM fs_key_wrap_receipts r
                          WHERE r.workspace_id = w.workspace_id
                            AND r.epoch_id = w.epoch_id
                            AND r.pubkey_id = w.pubkey_id
                            AND r.node_bit_len = w.node_bit_len
                            AND r.node_bytes = w.node_bytes)
         ORDER BY w.epoch_id ASC, w.pubkey_id ASC",
    )?;
    let rows = stmt
        .query_map(params![ws], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, Vec<u8>>(6)?,
                r.get::<_, Vec<u8>>(7)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::new();
    for (wrap, epoch, pubkey, node_bytes, node_bit_len, ciphertext, public_key, private_key) in rows
    {
        let pubkey_id = b64_to_id(&pubkey)?;
        let node_bytes = vec_to_id(node_bytes, "node_bytes")?;
        let private_key = vec_to_id(private_key, "private_key")?;
        let public_key = vec_to_id(public_key, "public_key")?;
        if public_key_for_private(&private_key) != public_key {
            continue;
        }
        if decrypt_wrap_payload(
            &ciphertext,
            &private_key,
            &public_key,
            &pubkey_id,
            &node_bytes,
            node_bit_len as u32,
        )
        .is_err()
        {
            continue;
        }
        out.push(ReceiptJob {
            wrap_id: b64_to_id(&wrap)?,
            epoch_id: b64_to_id(&epoch)?,
            pubkey_id,
            node_bytes,
            node_bit_len: node_bit_len as u32,
        });
    }
    Ok(out)
}

fn purge_ready_pubkeys(
    conn: &rusqlite::Connection,
    ws: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT p.pubkey_id
         FROM fs_pubkeys p
         WHERE p.workspace_id = ?1
           AND NOT EXISTS(SELECT 1 FROM fs_local_pubkey_purges lp
                          WHERE lp.workspace_id = p.workspace_id
                            AND lp.pubkey_id = p.pubkey_id)
           AND (
                EXISTS(SELECT 1 FROM fs_pubkey_tombstones t
                       WHERE t.workspace_id = p.workspace_id
                         AND t.pubkey_id = p.pubkey_id)
                OR EXISTS(SELECT 1 FROM fs_removed_recipients rr
                          WHERE rr.workspace_id = p.workspace_id
                            AND rr.recipient_id = p.recipient_id)
           )
         ORDER BY p.pubkey_id ASC",
    )?;
    let candidates = stmt
        .query_map(params![ws], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::new();
    for pubkey in candidates {
        let missing_receipts: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM fs_key_wraps w
             WHERE w.workspace_id = ?1
               AND w.pubkey_id = ?2
               AND NOT EXISTS(SELECT 1 FROM fs_key_wrap_receipts r
                              WHERE r.workspace_id = w.workspace_id
                                AND r.epoch_id = w.epoch_id
                                AND r.pubkey_id = w.pubkey_id
                                AND r.node_bit_len = w.node_bit_len
                                AND r.node_bytes = w.node_bytes)",
            params![ws, &pubkey],
            |r| r.get(0),
        )?;
        if missing_receipts == 0 {
            out.push(pubkey);
        }
    }
    Ok(out)
}

fn local_private_keys(
    conn: &rusqlite::Connection,
    ws: &str,
) -> Result<Vec<(String, EventId)>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT pubkey_id, private_key
         FROM fs_local_private_keys
         WHERE workspace_id = ?1
         ORDER BY pubkey_id ASC",
    )?;
    let rows = stmt
        .query_map(params![ws], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::new();
    for (pubkey, private_key) in rows {
        out.push((pubkey, vec_to_id(private_key, "private_key")?));
    }
    Ok(out)
}

fn materialize_unwrapped_nodes(
    conn: &rusqlite::Connection,
    ws: &str,
    pubkey: &str,
    private_key: &EventId,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let expected_public = public_key_for_private(private_key);
    let stored_public: Option<Vec<u8>> = conn
        .query_row(
            "SELECT public_key FROM fs_pubkeys
             WHERE workspace_id = ?1 AND pubkey_id = ?2",
            params![ws, pubkey],
            |r| r.get(0),
        )
        .optional()?;
    if stored_public
        .as_deref()
        .map(|public| public != &expected_public[..])
        .unwrap_or(true)
    {
        return Ok(0);
    }
    let mut stmt = conn.prepare(
        "SELECT epoch_id, node_bit_len, node_bytes, ciphertext
         FROM fs_key_wraps
         WHERE workspace_id = ?1 AND pubkey_id = ?2
         ORDER BY epoch_id ASC",
    )?;
    let wraps = stmt
        .query_map(params![ws, pubkey], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut inserted = 0usize;
    let pubkey_id = b64_to_id(pubkey)?;
    for (epoch, node_bit_len, node_bytes, ciphertext) in wraps {
        let node_bytes = vec_to_id(node_bytes, "node_bytes")?;
        let node_secret = match decrypt_wrap_payload(
            &ciphertext,
            private_key,
            &expected_public,
            &pubkey_id,
            &node_bytes,
            node_bit_len as u32,
        ) {
            Ok(secret) => secret,
            Err(_) => continue,
        };
        let changed = conn.execute(
            "INSERT OR IGNORE INTO fs_local_unwrapped_nodes
                (workspace_id, pubkey_id, epoch_id, node_bit_len, node_bytes, node_secret)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                ws,
                pubkey,
                epoch,
                node_bit_len,
                node_bytes.to_vec(),
                node_secret.to_vec()
            ],
        )?;
        inserted += changed;
    }
    Ok(inserted)
}

async fn emit_fs_event_and_wait(
    db_path: &Path,
    command_kind: &str,
    event: ParsedEvent,
    workspace_id: EventId,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_ready_connection(db_path)?;
    let emitted = emit_local_event(
        &conn,
        command_kind,
        &event,
        Some(workspace_id),
        EventScope::Durable,
    )?;
    drop(conn);
    let db = Arc::new(Mutex::new(open_connection(db_path)?));
    let status = wait_for_terminal(&db, &emitted.event_id, POLL_DEADLINE).await?;
    if status != EventStatus::Applied {
        return Err(format!("{} event not applied: {:?}", command_kind, status).into());
    }
    Ok(emitted.event_id)
}

fn open_ready_connection(
    db_path: &Path,
) -> Result<rusqlite::Connection, Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    ensure_infra_schema(&conn)?;
    Ok(conn)
}

fn current_workspace(db_path: &Path) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_ready_connection(db_path)?;
    let row: Option<Vec<u8>> = conn
        .query_row(
            "SELECT workspace_id FROM events_canonical
             WHERE workspace_id IS NOT NULL
               AND status = 'applied'
             ORDER BY created_at_ms DESC, event_id DESC
             LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    row.map(|v| vec_to_id(v, "workspace_id"))
        .transpose()?
        .ok_or_else(|| "no applied workspace - run create-workspace first".into())
}

fn is_locally_purged(
    conn: &rusqlite::Connection,
    ws: &str,
    pubkey: &str,
) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM fs_local_pubkey_purges
         WHERE workspace_id = ?1 AND pubkey_id = ?2)",
        params![ws, pubkey],
        |r| r.get(0),
    )
}

fn parse_id(raw: &str, field: &str) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    event_id_from_hex(raw)
        .or_else(|| event_id_from_base64(raw))
        .ok_or_else(|| format!("{field} must be a 32-byte hex or base64 id").into())
}

fn b64_to_id(raw: &str) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    event_id_from_base64(raw)
        .ok_or_else(|| format!("invalid base64 event id in database: {raw}").into())
}

fn vec_to_id(
    bytes: Vec<u8>,
    field: &str,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    if bytes.len() != 32 {
        return Err(format!("{field} must be 32 bytes, got {}", bytes.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn id_b64(id: &EventId) -> String {
    event_id_to_base64(id)
}

fn hex_id(id: &EventId) -> String {
    hex::encode(id)
}

fn hex_from_b64(raw: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    Ok(hex_id(&b64_to_id(raw)?))
}

fn hash_parts(parts: &[&[u8]]) -> EventId {
    let mut h = blake3::Hasher::new();
    for part in parts {
        h.update(&(part.len() as u64).to_le_bytes());
        h.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn parse_private_key_hex(raw: &str) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = hex::decode(raw.trim())?;
    vec_to_id(bytes, "private_key")
}

fn public_key_for_private(private_key: &EventId) -> EventId {
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

fn root_commitment(root_secret: &EventId) -> EventId {
    hash_parts(&[b"fs-root-commitment-v1", root_secret])
}

fn secret_commitment(root_secret: &EventId, node_bytes: &EventId, node_bit_len: u32) -> EventId {
    hash_parts(&[
        b"fs-secret-commitment-v1",
        root_secret,
        node_bytes,
        &node_bit_len.to_le_bytes(),
    ])
}

fn local_epoch_root(
    conn: &rusqlite::Connection,
    ws: &str,
    epoch: &str,
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    conn.query_row(
        "SELECT root_secret FROM fs_local_epoch_roots
         WHERE workspace_id = ?1 AND epoch_id = ?2",
        params![ws, epoch],
        |r| r.get::<_, Vec<u8>>(0),
    )
    .optional()?
    .map(|bytes| vec_to_id(bytes, "root_secret"))
    .transpose()
}

fn message_key(node_secret: &EventId, leaf: &EventId) -> EventId {
    hash_parts(&[b"fs-message-key-v1", node_secret, leaf])
}

fn deterministic_nonce(domain: &[u8], parts: &[&[u8]]) -> [u8; AES_GCM_NONCE_BYTES] {
    let mut h = blake3::Hasher::new();
    h.update(&(domain.len() as u64).to_le_bytes());
    h.update(domain);
    for part in parts {
        h.update(&(part.len() as u64).to_le_bytes());
        h.update(part);
    }
    let digest = h.finalize();
    let mut out = [0u8; AES_GCM_NONCE_BYTES];
    out.copy_from_slice(&digest.as_bytes()[..AES_GCM_NONCE_BYTES]);
    out
}

fn encrypt_aes_gcm(
    key: &EventId,
    nonce: &[u8; AES_GCM_NONCE_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "invalid AES-GCM key length")?;
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| "AES-GCM encryption failed".into())
}

fn decrypt_aes_gcm(
    key: &EventId,
    nonce: &[u8; AES_GCM_NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "invalid AES-GCM key length")?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "AES-GCM authentication failed".into())
}

fn pack_nonce_ciphertext(nonce: &[u8; AES_GCM_NONCE_BYTES], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AES_GCM_NONCE_BYTES + ciphertext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

fn unpack_nonce_ciphertext(
    payload: &[u8],
) -> Result<([u8; AES_GCM_NONCE_BYTES], &[u8]), Box<dyn std::error::Error + Send + Sync>> {
    if payload.len() < AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES {
        return Err("encrypted payload is too short".into());
    }
    let mut nonce = [0u8; AES_GCM_NONCE_BYTES];
    nonce.copy_from_slice(&payload[..AES_GCM_NONCE_BYTES]);
    Ok((nonce, &payload[AES_GCM_NONCE_BYTES..]))
}

fn encrypt_wrap_payload(
    root_secret: &EventId,
    pubkey_id: &EventId,
    recipient_public: &EventId,
    node_bytes: &EventId,
    node_bit_len: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let node_bit_len_bytes = node_bit_len.to_le_bytes();
    let ephemeral_seed = hash_parts(&[
        b"fs-wrap-ephemeral-v1",
        root_secret,
        pubkey_id,
        recipient_public,
        node_bytes,
        &node_bit_len_bytes,
    ]);
    let ephemeral_secret = StaticSecret::from(ephemeral_seed);
    let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();
    let recipient_public_key = PublicKey::from(*recipient_public);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public_key);
    let key = hash_parts(&[
        b"fs-wrap-key-v1",
        shared.as_bytes(),
        pubkey_id,
        recipient_public,
        &ephemeral_public,
        node_bytes,
        &node_bit_len_bytes,
    ]);
    let nonce = deterministic_nonce(
        b"fs-wrap-nonce-v1",
        &[
            pubkey_id,
            recipient_public,
            &ephemeral_public,
            node_bytes,
            &node_bit_len_bytes,
        ],
    );
    let ciphertext = encrypt_aes_gcm(&key, &nonce, root_secret)?;
    let mut payload =
        Vec::with_capacity(X25519_PUBLIC_BYTES + AES_GCM_NONCE_BYTES + ciphertext.len());
    payload.extend_from_slice(&ephemeral_public);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

fn decrypt_wrap_payload(
    payload: &[u8],
    recipient_private: &EventId,
    expected_public: &EventId,
    pubkey_id: &EventId,
    node_bytes: &EventId,
    node_bit_len: u32,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    if public_key_for_private(recipient_private) != *expected_public {
        return Err("private key does not match recipient public key".into());
    }
    if payload.len() < X25519_PUBLIC_BYTES + AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES {
        return Err("wrap payload is too short".into());
    }
    let mut ephemeral_public = [0u8; X25519_PUBLIC_BYTES];
    ephemeral_public.copy_from_slice(&payload[..X25519_PUBLIC_BYTES]);
    let mut nonce = [0u8; AES_GCM_NONCE_BYTES];
    nonce.copy_from_slice(&payload[X25519_PUBLIC_BYTES..X25519_PUBLIC_BYTES + AES_GCM_NONCE_BYTES]);
    let ciphertext = &payload[X25519_PUBLIC_BYTES + AES_GCM_NONCE_BYTES..];
    let recipient_secret = StaticSecret::from(*recipient_private);
    let shared = recipient_secret.diffie_hellman(&PublicKey::from(ephemeral_public));
    let node_bit_len_bytes = node_bit_len.to_le_bytes();
    let key = hash_parts(&[
        b"fs-wrap-key-v1",
        shared.as_bytes(),
        pubkey_id,
        expected_public,
        &ephemeral_public,
        node_bytes,
        &node_bit_len_bytes,
    ]);
    let plaintext = decrypt_aes_gcm(&key, &nonce, ciphertext)?;
    vec_to_id(plaintext, "node_secret")
}

fn decrypt_message_payload(
    node_secret: &EventId,
    leaf: &EventId,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let message_key = message_key(node_secret, leaf);
    let (nonce, ciphertext) = unpack_nonce_ciphertext(payload)?;
    decrypt_aes_gcm(&message_key, &nonce, ciphertext)
}

fn history_leaf(epoch_id: &EventId, unix_minute: u64, coord_event_id: &EventId) -> EventId {
    hash_parts(&[
        b"fs-history-leaf-v1",
        epoch_id,
        &unix_minute.to_le_bytes(),
        coord_event_id,
    ])
}

fn prefix_contains(prefix: &[u8], bit_len: u32, leaf: &EventId) -> bool {
    if bit_len == 0 {
        return true;
    }
    if bit_len > 256 || prefix.len() < 32 {
        return false;
    }
    let full_bytes = (bit_len / 8) as usize;
    let rem_bits = (bit_len % 8) as u8;
    if prefix[..full_bytes] != leaf[..full_bytes] {
        return false;
    }
    if rem_bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem_bits);
    (prefix[full_bytes] & mask) == (leaf[full_bytes] & mask)
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
