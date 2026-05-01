//! # `topo` — minimal viable daemon binary
//!
//! Post-#47 the historical daemon (`runtime/main.rs`, `node.rs`,
//! `runtime_manager.rs`, `control_loop_node.rs`) was deleted wholesale.
//! This binary is the substrate-only replacement: a thin CLI shell that
//! either starts the new `ControlLoopRuntime` or drives a single
//! locally-emitted event intent through it.
//!
//! ## Subcommands
//!
//! - `topo --db <path> start --bind <ip:port>` — start the daemon. Spawns
//!   a [`ControlLoopRuntime`] and blocks until SIGINT / SIGTERM.
//! - `topo --db <path> stop` — write a `local_event_intents` row of
//!   kind `daemon_stop` (best effort). The current substrate has no
//!   in-band shutdown channel for an external CLI process; daemons
//!   shut down on signal. This subcommand exists so wrappers / tests
//!   can record an intent to stop, but it does not actually deliver a
//!   signal — that is the supervisor's job.
//! - `topo --db <path> status` — print the listen address (if known
//!   from the daemon-identity table) and a summary of the
//!   `events_canonical` / `workspaces` projection.
//! - `topo --db <path> create-workspace <name>` — emit a Workspace
//!   event through the local-intent helper. Polls
//!   `events_canonical[event_id].status` until Applied / Rejected.
//! - `topo --db <path> accept-invite <invite-blob>` — emit an
//!   InviteAccepted event. The invite blob is a hex-encoded
//!   `(invite_event_id, workspace_id, tenant_event_id)` triple — full
//!   invite-link parsing is intentionally out of scope for this minimal
//!   binary; the test harness builds the blob explicitly.
//! - `topo --db <path> send <message>` — emit a Message event.
//!   Requires a workspace to exist.
//! - `topo --db <path> messages` — query the `messages` projection.
//!
//! ## Local-event intent flow
//!
//! For every "emit" subcommand, the binary calls
//! [`topo::local_intents::emit_local_event`] which:
//!
//! 1. Encodes the event to canonical bytes.
//! 2. Inserts a `local_event_intents` row (audit / diagnostics).
//! 3. Admits the event into `events_canonical` at status `ready`.
//! 4. Notifies the dispatcher's wake bus on the local-events + ready
//!    queues.
//!
//! The dispatcher's existing `drain_ready` step picks the row up,
//! runs parse → context → project → apply, and transitions the row to
//! Applied / Blocked / Rejected. The binary polls until terminal.

mod fs_cli;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use rusqlite::params;
use tokio::signal;

use topo::event_modules::{
    InviteAcceptedEvent, MessageEvent, ParsedEvent, WorkspaceEvent,
};
use topo::local_intents::{emit_local_event, wait_for_terminal};
use topo::runtime::control_loop::ControlLoopRuntime;
use topo::state::db::{ensure_infra_schema, open_connection};
use topo::state::events_canonical::{EventScope, EventStatus};

const POLL_DEADLINE: Duration = Duration::from_secs(120);

#[derive(Parser, Debug)]
#[command(name = "topo")]
#[command(about = "topo — minimal substrate daemon")]
struct Cli {
    /// Database path.
    #[arg(short, long, default_value = "topo.db", global = true)]
    db: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the daemon and block on shutdown signal.
    Start {
        /// Bind address for the substrate transport listener.
        #[arg(short, long, default_value = "127.0.0.1:0")]
        bind: SocketAddr,
    },

    /// Record a stop intent (out-of-process supervisor must deliver the signal).
    Stop,

    /// Print listen address and a workspace/event summary.
    Status,

    /// Emit a Workspace event.
    #[command(name = "create-workspace")]
    CreateWorkspace {
        /// Workspace display name.
        name: String,
    },

    /// Emit an InviteAccepted event from a hex-encoded
    /// (invite_event_id || workspace_id || tenant_event_id) blob (96 bytes).
    #[command(name = "accept-invite")]
    AcceptInvite {
        /// Hex-encoded 96-byte blob.
        invite_blob: String,
    },

    /// Emit a Message event under the most-recently-applied workspace.
    Send {
        /// Message content.
        content: String,
    },

    /// List applied Message events.
    Messages {
        /// Maximum messages to print (0 = unlimited).
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Exercise forward-secret encryption facts and deterministic maintenance.
    Fs {
        #[command(subcommand)]
        command: fs_cli::FsCommand,
    },
}

fn main() {
    let cli = Cli::parse();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
        rt.block_on(async move { run(cli).await });

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db_path = PathBuf::from(&cli.db);
    match cli.command {
        Commands::Start { bind } => cmd_start(&db_path, bind).await,
        Commands::Stop => cmd_stop(&db_path),
        Commands::Status => cmd_status(&db_path),
        Commands::CreateWorkspace { name } => cmd_create_workspace(&db_path, &name).await,
        Commands::AcceptInvite { invite_blob } => {
            cmd_accept_invite(&db_path, &invite_blob).await
        }
        Commands::Send { content } => cmd_send(&db_path, &content).await,
        Commands::Messages { limit } => cmd_messages(&db_path, limit),
        Commands::Fs { command } => fs_cli::run(&db_path, command).await,
    }
}

// ---------------------------------------------------------------------------
// `start`
// ---------------------------------------------------------------------------

async fn cmd_start(
    db_path: &std::path::Path,
    bind: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Use a deterministic-but-distinct local endpoint id derived from
    // the bind address. Real keying lives in `legacy_identity`; for the
    // minimal binary we just need a stable 32-byte tag.
    let local_endpoint_id = derive_endpoint_id(db_path);
    let handles = ControlLoopRuntime::start(bind, local_endpoint_id, db_path).await?;
    let listen = handles.runtime.listen_addr;
    println!("topo: listening on {}", listen);
    println!("topo: db = {}", db_path.display());
    println!("topo: press ctrl-c to shut down");

    // Block on ctrl-c.
    signal::ctrl_c().await?;
    println!("topo: shutdown signal received");
    ControlLoopRuntime::shutdown(handles).await?;
    Ok(())
}

fn derive_endpoint_id(db_path: &std::path::Path) -> [u8; 32] {
    // Deterministic placeholder: BLAKE3(canonical(db_path)). The real
    // daemon derives this from a persistent ed25519 keypair (see
    // `legacy_identity::ensure_daemon_identity`); the minimal binary
    // doesn't need that for the local-event chain because no remote
    // peer is involved.
    let canonical = std::fs::canonicalize(db_path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| db_path.to_string_lossy().to_string());
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(canonical.as_bytes()).as_bytes());
    id
}

// ---------------------------------------------------------------------------
// `stop`
// ---------------------------------------------------------------------------

fn cmd_stop(
    db_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    ensure_infra_schema(&conn)?;
    conn.execute(
        "INSERT INTO local_event_intents (command_kind, payload, enqueued_at_ms, status)
         VALUES ('daemon_stop', x'', ?1, 'pending')",
        params![now_ms()],
    )?;
    println!("topo: stop intent recorded");
    println!(
        "topo: NOTE — the substrate has no in-band shutdown RPC yet; \
         deliver SIGINT / SIGTERM to the daemon process to actually shut down."
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// `status`
// ---------------------------------------------------------------------------

fn cmd_status(
    db_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    ensure_infra_schema(&conn)?;

    println!("db = {}", db_path.display());

    // events_canonical summary.
    let mut stmt = conn.prepare(
        "SELECT status, COUNT(*) FROM events_canonical GROUP BY status",
    )?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        println!("events_canonical: <empty>");
    } else {
        println!("events_canonical:");
        for (status, count) in rows {
            println!("  {:>10} = {}", status, count);
        }
    }

    // workspaces projection summary (registry-driven schema is created
    // by ensure_infra_schema; rows arrive when a Workspace event applies).
    let n_ws: i64 = conn
        .query_row("SELECT COUNT(*) FROM workspaces", [], |r| r.get(0))
        .unwrap_or(0);
    println!("workspaces (projection): {}", n_ws);

    // local_event_intents tail.
    let n_intents: i64 = conn
        .query_row("SELECT COUNT(*) FROM local_event_intents", [], |r| r.get(0))
        .unwrap_or(0);
    println!("local_event_intents: {}", n_intents);

    Ok(())
}

// ---------------------------------------------------------------------------
// `create-workspace`
// ---------------------------------------------------------------------------

async fn cmd_create_workspace(
    db_path: &std::path::Path,
    name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if name.as_bytes().len() > topo::event_modules::layout::common::NAME_BYTES {
        return Err(format!(
            "workspace name too long: {} bytes, max {}",
            name.len(),
            topo::event_modules::layout::common::NAME_BYTES
        )
        .into());
    }

    let conn = open_connection(db_path)?;
    ensure_infra_schema(&conn)?;

    // Deterministic-but-fresh public key: BLAKE3 of (db_path || name || time).
    let pubkey = derive_workspace_pubkey(db_path, name);
    let ws = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms() as u64,
        workspace_id: pubkey,
        public_key: pubkey,
        name: name.to_string(),
    });

    let emitted = emit_local_event(&conn, "create_workspace", &ws, None, EventScope::Durable)?;
    drop(conn);

    println!(
        "topo: emitted Workspace event {} (intent_row_id={})",
        hex::encode(emitted.event_id),
        emitted.intent_row_id
    );

    let db = std::sync::Arc::new(tokio::sync::Mutex::new(open_connection(db_path)?));
    let status = wait_for_terminal(&db, &emitted.event_id, POLL_DEADLINE).await?;
    println!("topo: workspace event reached terminal status {:?}", status);
    if status != EventStatus::Applied {
        return Err(format!("workspace not applied: {:?}", status).into());
    }
    Ok(())
}

fn derive_workspace_pubkey(db_path: &std::path::Path, name: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(db_path.to_string_lossy().as_bytes());
    h.update(b"\x00");
    h.update(name.as_bytes());
    h.update(b"\x00");
    h.update(&now_ms().to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

// ---------------------------------------------------------------------------
// `accept-invite`
// ---------------------------------------------------------------------------

async fn cmd_accept_invite(
    db_path: &std::path::Path,
    invite_blob_hex: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let blob = hex::decode(invite_blob_hex)
        .map_err(|e| format!("invalid hex blob: {}", e))?;
    if blob.len() != 96 {
        return Err(format!(
            "invite blob must be exactly 96 bytes (got {})",
            blob.len()
        )
        .into());
    }
    let mut invite_event_id = [0u8; 32];
    let mut workspace_id = [0u8; 32];
    let mut tenant_event_id = [0u8; 32];
    invite_event_id.copy_from_slice(&blob[0..32]);
    workspace_id.copy_from_slice(&blob[32..64]);
    tenant_event_id.copy_from_slice(&blob[64..96]);

    let conn = open_connection(db_path)?;
    ensure_infra_schema(&conn)?;

    let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms() as u64,
        tenant_event_id,
        invite_event_id,
        workspace_id,
    });

    let emitted = emit_local_event(
        &conn,
        "accept_invite",
        &ia,
        Some(workspace_id),
        EventScope::Durable,
    )?;
    drop(conn);

    println!(
        "topo: emitted InviteAccepted event {} (intent_row_id={})",
        hex::encode(emitted.event_id),
        emitted.intent_row_id
    );

    let db = std::sync::Arc::new(tokio::sync::Mutex::new(open_connection(db_path)?));
    let status = wait_for_terminal(&db, &emitted.event_id, POLL_DEADLINE).await?;
    println!(
        "topo: invite_accepted event reached terminal status {:?}",
        status
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// `send`
// ---------------------------------------------------------------------------

async fn cmd_send(
    db_path: &std::path::Path,
    content: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    ensure_infra_schema(&conn)?;

    // Pick the most recently created applied workspace.
    let workspace_id = lookup_recent_workspace_id(&conn)?
        .ok_or("no applied workspace — run create-workspace first")?;

    // Author/signer ids: stable per-db tags. The minimal binary doesn't
    // run identity setup; the projector currently only requires the
    // event's `content` to be non-empty + no removed/deleted labels.
    let author_id = derive_author_id(db_path);
    let signer_id = author_id;

    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: now_ms() as u64,
        workspace_id,
        author_id,
        content: content.to_string(),
        signed_by: signer_id,
        signer_type: 5,
        signature: [0u8; 64],
    });

    let emitted = emit_local_event(
        &conn,
        "send_message",
        &msg,
        Some(workspace_id),
        EventScope::Durable,
    )?;
    drop(conn);

    println!(
        "topo: emitted Message event {} (intent_row_id={})",
        hex::encode(emitted.event_id),
        emitted.intent_row_id
    );

    let db = std::sync::Arc::new(tokio::sync::Mutex::new(open_connection(db_path)?));
    let status = wait_for_terminal(&db, &emitted.event_id, POLL_DEADLINE).await?;
    println!("topo: message event reached terminal status {:?}", status);
    if status != EventStatus::Applied {
        return Err(format!("message not applied: {:?}", status).into());
    }
    Ok(())
}

fn lookup_recent_workspace_id(
    conn: &rusqlite::Connection,
) -> Result<Option<[u8; 32]>, rusqlite::Error> {
    use rusqlite::OptionalExtension;
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
    Ok(row.and_then(|v| {
        if v.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&v);
            Some(id)
        } else {
            None
        }
    }))
}

fn derive_author_id(db_path: &std::path::Path) -> [u8; 32] {
    let canonical = std::fs::canonicalize(db_path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| db_path.to_string_lossy().to_string());
    let mut h = blake3::Hasher::new();
    h.update(b"topo-author:");
    h.update(canonical.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

// ---------------------------------------------------------------------------
// `messages`
// ---------------------------------------------------------------------------

fn cmd_messages(
    db_path: &std::path::Path,
    limit: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    ensure_infra_schema(&conn)?;

    let sql = if limit > 0 {
        format!(
            "SELECT message_id, workspace_id, author_id, content, created_at
                FROM messages
                ORDER BY created_at ASC, message_id ASC
                LIMIT {}",
            limit
        )
    } else {
        "SELECT message_id, workspace_id, author_id, content, created_at
            FROM messages
            ORDER BY created_at ASC, message_id ASC"
            .to_string()
    };
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(MessageItem {
                message_id: r.get(0)?,
                workspace_id: r.get(1)?,
                author_id: r.get(2)?,
                content: r.get(3)?,
                created_at: r.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if rows.is_empty() {
        println!("(no messages)");
    } else {
        for (i, m) in rows.iter().enumerate() {
            println!(
                "[{}] ws={} author={} created_at={} :: {}",
                i + 1,
                short_b64(&m.workspace_id),
                short_b64(&m.author_id),
                m.created_at,
                m.content
            );
        }
    }
    Ok(())
}

struct MessageItem {
    #[allow(dead_code)]
    message_id: String,
    workspace_id: String,
    author_id: String,
    content: String,
    created_at: i64,
}

fn short_b64(s: &str) -> &str {
    &s[..s.len().min(8)]
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
