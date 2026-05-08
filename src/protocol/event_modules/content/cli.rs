//! Content domain CLI for cross-module flows.
//!
//! bundle. The bundle threads the parent message's content key
//! (`(removal_frontier_id, local_key_secret_id, key_secret)`) into the file
//! and slice commands so descriptor metadata and slice payloads ride encrypted
//! over the wire under the same AEAD key as the message text.
//!
//! `view` is the canonical cross-module read view: it joins the local endpoint
//! identity, workspace name, user/device list, and the message stream with
//! inline reactions and file attachments. Both commands span multiple child
//! modules, so they live at the content domain root rather than any leaf
//! `cli.rs`. Leaf-module CLI files keep per-event read/write commands.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::crypto;
use crate::core::crypto::XCHACHA20_POLY1305_TAG_BYTES;
use crate::core::store::Store;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::{file, file_slice, message};
use crate::protocol::event_modules::identity::{endpoint, endpoint_shared, user, workspace};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{self, CommandOutput, ProposedEvent};

const SEND_FILE_USAGE: &str = "send-file WORKSPACE_ID_HEX TEXT --file PATH [--mime MIME]";
const VIEW_USAGE: &str = "view [WORKSPACE_ID_HEX]";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "send-file",
            usage: SEND_FILE_USAGE,
            help: "Send a message with an attached file from disk.",
            run: run_send_file_command,
        },
        CliCommand {
            name: "view",
            usage: VIEW_USAGE,
            help: "Render the workspace sidebar and chronological message stream.",
            run: run_view_command,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFileSummary {
    pub message_id: EventId,
    pub file_event_id: EventId,
    pub file_id: EventId,
    pub filename: String,
    pub mime_type: String,
    pub blob_bytes: u64,
    pub total_slices: u32,
}

impl SendFileSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("event_id: {}", message::cli::hex_id(self.message_id)),
            format!(
                "file_event_id: {}",
                message::cli::hex_id(self.file_event_id)
            ),
            format!("file_id: {}", message::cli::hex_id(self.file_id)),
            format!("filename: {}", self.filename),
            format!("mime: {}", self.mime_type),
            format!("blob_bytes: {}", self.blob_bytes),
            format!("total_slices: {}", self.total_slices),
        ]
    }
}

fn run_send_file_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let parsed = SendFileArgs::parse(args)?;

    let membership = message::cli::require_membership(&context.store, parsed.workspace_id)?;
    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    if membership.signing_public_key != local.signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }

    let plaintext = fs::read(&parsed.file_path)
        .map_err(|err| format!("read {}: {err}", parsed.file_path.display()))?;
    let blob_bytes = plaintext.len() as u64;
    let slice_bytes = u32::try_from(file_slice::types::FILE_SLICE_DATA_BYTES)
        .map_err(|_| "slice budget overflows u32".to_string())?;
    let total_slices = if blob_bytes == 0 {
        0
    } else {
        u32::try_from(
            plaintext
                .len()
                .div_ceil(file_slice::types::FILE_SLICE_DATA_BYTES),
        )
        .map_err(|_| "slice count overflows u32".to_string())?
    };
    let filename = parsed
        .file_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "file path is not valid utf-8".to_string())?
        .to_string();

    let starting_timestamp = message::cli::next_timestamp(&context.store, parsed.workspace_id)?;
    let mut timestamp = starting_timestamp;
    let removal_frontier_id =
        message::cli::require_active_frontier_id(&context.store, parsed.workspace_id)?;
    let signer_endpoint = membership.endpoint_shared_id;
    let author_user_id = membership.user_authority_event_id;

    // Derive the message's own per-event leaf using the deterministic coord
    // computed from canonical message fields.
    let message_event_coord = message::types::message_event_id_in_minute(
        &parsed.workspace_id,
        &author_user_id,
        &removal_frontier_id,
        timestamp,
    );
    let message_leaf = message::cli::derive_message_leaf(
        &context.store,
        &context.protocol,
        parsed.workspace_id,
        removal_frontier_id,
        timestamp,
        message_event_coord,
    )?;

    // Send-message event under the message's own content key.
    let send = message::commands::send(message::commands::SendMessage {
        workspace_id: parsed.workspace_id,
        created_at_ms: timestamp,
        author_user_id,
        signer_endpoint_shared_id: signer_endpoint,
        signer_private_key: local.signing_secret,
        removal_frontier_id,
        local_history_node_secret_id: message_leaf.local_history_node_secret_id,
        leaf_node_secret: message_leaf.leaf_node_secret,
        text: parsed.text,
    })?;
    let message_id = send.value.message_id;
    timestamp = timestamp.saturating_add(1);

    let file_id = derive_file_id(&signer_endpoint, message_id, starting_timestamp);

    // Files now author their own leaf, distinct from the parent message's
    // leaf. Two clients independently authoring the same file (same
    // workspace, author, parent message, file_id, frontier, timestamp) reach
    // the same leaf coord and admission collapses the duplicate.
    let file_event_coord = file::types::file_event_id_in_minute(
        &parsed.workspace_id,
        &author_user_id,
        &message_id,
        &file_id,
        &removal_frontier_id,
        timestamp,
    );
    let file_leaf = message::cli::derive_message_leaf(
        &context.store,
        &context.protocol,
        parsed.workspace_id,
        removal_frontier_id,
        timestamp,
        file_event_coord,
    )?;

    // Encrypt each plaintext slice with the file's own leaf node secret.
    // Slice AAD is independent of file_event_id (see file_slice::codec
    // docs), so a single seal pass + BAO outboard suffices.
    let mut ciphertext_total = Vec::with_capacity(
        plaintext.len() + (total_slices as usize) * XCHACHA20_POLY1305_TAG_BYTES,
    );
    for slice_number in 0..total_slices {
        let start = (slice_number as usize) * slice_bytes as usize;
        let end = ((slice_number + 1) as usize * slice_bytes as usize).min(plaintext.len());
        let chunk = file_slice::codec::seal_slice(
            &file_leaf.leaf_node_secret,
            &parsed.workspace_id,
            &file_id,
            slice_number,
            &signer_endpoint,
            &plaintext[start..end],
        )?;
        ciphertext_total.extend_from_slice(&chunk);
    }
    let (root_hash, outboard) = if ciphertext_total.is_empty() {
        ([0u8; 32], Vec::new())
    } else {
        crypto::bao_outboard(&ciphertext_total)?
    };

    let create_file = file::commands::create(file::commands::CreateFile {
        workspace_id: parsed.workspace_id,
        created_at_ms: timestamp,
        message_id,
        author_user_id,
        signer_endpoint_shared_id: signer_endpoint,
        signer_private_key: local.signing_secret,
        file_id,
        blob_bytes,
        total_slices,
        slice_bytes,
        root_hash,
        filename: filename.clone(),
        mime_type: parsed.mime_type.clone(),
        removal_frontier_id,
        local_history_node_secret_id: file_leaf.local_history_node_secret_id,
        key_secret: file_leaf.leaf_node_secret,
    })?;
    let file_event_id = create_file.value.file_event_id;
    timestamp = timestamp.saturating_add(1);

    let mut bundled: Vec<ProposedEvent> = Vec::new();
    bundled.extend(send.events);
    bundled.extend(create_file.events);

    for slice_number in 0..total_slices {
        let plaintext_start = (slice_number as usize) * slice_bytes as usize;
        let plaintext_end =
            ((slice_number + 1) as usize * slice_bytes as usize).min(plaintext.len());
        let plaintext_len = (plaintext_end - plaintext_start) as u32;
        let chunk_size = u64::from(slice_bytes) + XCHACHA20_POLY1305_TAG_BYTES as u64;
        let slice_start = u64::from(slice_number) * chunk_size;
        let slice_len = u64::from(plaintext_len) + XCHACHA20_POLY1305_TAG_BYTES as u64;
        let slice = file_slice::commands::slice_from_ciphertext(
            file_slice::commands::SliceFromCiphertext {
                workspace_id: parsed.workspace_id,
                created_at_ms: timestamp,
                file_id,
                file_event_id,
                slice_number,
                signer_endpoint_shared_id: signer_endpoint,
                signer_private_key: local.signing_secret,
                local_history_node_secret_id: file_leaf.local_history_node_secret_id,
                plaintext_len,
                ciphertext: &ciphertext_total,
                outboard: &outboard,
                slice_start,
                slice_len,
            },
        )?;
        bundled.extend(slice.events);
        timestamp = timestamp.saturating_add(1);
    }

    let summary = SendFileSummary {
        message_id,
        file_event_id,
        file_id,
        filename,
        mime_type: parsed.mime_type,
        blob_bytes,
        total_slices,
    };
    let output = CommandOutput::with_proposed_events(summary, bundled);
    let report = worker::run(
        &context.store,
        &context.protocol,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit send-file bundle: {err}"))?;
    if report.admitted.inserted_events == 0 {
        return Err("send-file bundle was not admitted".to_string());
    }
    Ok(CliOutput::lines(report.value.lines()))
}

struct SendFileArgs {
    workspace_id: EventId,
    text: String,
    file_path: PathBuf,
    mime_type: String,
}

impl SendFileArgs {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        if args.values().len() < 4 {
            return Err(SEND_FILE_USAGE.to_string());
        }
        let workspace_id =
            message::cli::parse_hex_id(args.get(0).expect("length checked"), SEND_FILE_USAGE)?;
        let text = args.get(1).expect("length checked").to_string();
        let mut file_path = None;
        let mut mime_type = "application/octet-stream".to_string();
        let mut idx = 2usize;
        while idx < args.values().len() {
            match args.get(idx).expect("index in bounds") {
                "--file" => {
                    let path = args
                        .get(idx + 1)
                        .ok_or_else(|| SEND_FILE_USAGE.to_string())?;
                    file_path = Some(PathBuf::from(path));
                    idx += 2;
                }
                "--mime" => {
                    let value = args
                        .get(idx + 1)
                        .ok_or_else(|| SEND_FILE_USAGE.to_string())?;
                    mime_type = value.to_string();
                    idx += 2;
                }
                _ => return Err(SEND_FILE_USAGE.to_string()),
            }
        }
        let file_path = file_path.ok_or_else(|| SEND_FILE_USAGE.to_string())?;
        Ok(Self {
            workspace_id,
            text,
            file_path,
            mime_type,
        })
    }
}

fn derive_file_id(
    signer_endpoint_shared_id: &EventId,
    message_id: EventId,
    starting_timestamp: u64,
) -> EventId {
    let mut input = Vec::with_capacity(
        "poc8-content-file-id\0".len()
            + signer_endpoint_shared_id.len()
            + message_id.len()
            + std::mem::size_of::<u64>(),
    );
    input.extend_from_slice(b"poc8-content-file-id\0");
    input.extend_from_slice(signer_endpoint_shared_id);
    input.extend_from_slice(&message_id);
    input.extend_from_slice(&starting_timestamp.to_be_bytes());
    crypto::hash(&input)
}

// --------------------------------------------------------------------------
// `view` rendering
// --------------------------------------------------------------------------
//
// `view` renders a chat-style sidebar plus a chronological message stream for
// one workspace. It is read-only: it never creates events or drives workers.
// The output format mirrors poc-7's `view` byte-for-byte where reasonable so
// existing chat UI muscle memory and screenshots transfer over. The two
// deliberate divergences are:
//
//   * `IDENTITY:` replaces `TENANTS:`. poc-8 has no tenant concept; the local
//     endpoint identity is the closest equivalent and matches the existing
//     `topo identity` output for consistency.
//   * `WORKSPACE_ID_HEX` is optional. When the local endpoint is joined to
//     exactly one workspace, `view` picks it; otherwise it errors with a
//     workspace-selection message.

fn run_view_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let arg = match args.values() {
        [] => None,
        [value] => Some(value.as_str()),
        _ => return Err(VIEW_USAGE.to_string()),
    };

    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let joined =
        endpoint_shared::schema::workspace_ids_for_endpoint(&context.store, local.endpoint)?;

    let workspace_id = match arg {
        Some(value) => message::cli::parse_hex_id(value, VIEW_USAGE)?,
        None => match joined.len() {
            0 => return Err("no joined workspaces; create or accept one first".to_string()),
            1 => joined[0],
            _ => return Err("select a workspace: pass WORKSPACE_ID_HEX".to_string()),
        },
    };

    if !joined.contains(&workspace_id) {
        return Err("local endpoint has not joined this workspace".to_string());
    }

    let workspace_value = context
        .store
        .table_row(workspace::schema::WORKSPACES, &workspace_id)
        .map_err(|err| format!("load workspace: {err}"))?
        .ok_or_else(|| "workspace row is missing".to_string())?;
    let workspace_row = workspace::schema::decode_workspace_row(&workspace_id, &workspace_value)?;

    let users = workspace_user_view(&context.store, workspace_id, local.endpoint)?;
    let messages = message::cli::list_for_display(&context.store, workspace_id, 0)?;
    let files_by_message = {
        let mut grouped: std::collections::BTreeMap<EventId, Vec<file::types::FileRow>> =
            std::collections::BTreeMap::new();
        for row in file::cli::visible_file_rows(&context.store, workspace_id)? {
            grouped.entry(row.message_id).or_default().push(row);
        }
        grouped
    };
    let reactions = reactions_with_authors(&context.store, workspace_id)?;

    let now_ms = current_unix_ms();
    let mut lines = Vec::new();
    lines.push("IDENTITY:".to_string());
    lines.push(format!(
        "  endpoint_id: {}",
        message::cli::hex_id(local.endpoint)
    ));
    lines.push(format!(
        "  signing_public_key: {}",
        message::cli::hex_id(local.signing_public_key)
    ));
    lines.push(String::new());
    lines.push("WORKSPACE:".to_string());
    lines.push(format!("  {}", workspace_row.name));
    lines.push(String::new());
    lines.push("  USERS:".to_string());
    if users.is_empty() {
        lines.push("    (none)".to_string());
    } else {
        for user_row in &users {
            let label = format!("{}/{}", user_row.username, user_row.device_name);
            if user_row.is_local {
                lines.push(format!("    {} (you)", label));
            } else {
                lines.push(format!("    {}", label));
            }
        }
    }

    lines.push(String::new());
    lines.push(format!("  {}", "\u{2500}".repeat(40)));
    lines.push(String::new());

    if messages.is_empty() {
        lines.push("    (no messages)".to_string());
    } else {
        let username_by_user: BTreeMap<EventId, String> = users
            .iter()
            .map(|row| (row.user_id, row.username.clone()))
            .collect();
        let mut last_author: Option<EventId> = None;
        for (idx, msg) in messages.iter().enumerate() {
            if last_author != Some(msg.author_user_id) {
                if idx > 0 {
                    lines.push(String::new());
                }
                lines.push(format!(
                    "    {} [{}]",
                    msg.author_username,
                    format_age_ms(now_ms, msg.created_at_ms),
                ));
                last_author = Some(msg.author_user_id);
            }
            lines.push(format!("      {}. {}", msg.index, msg.text));
            if let Some(emoji_authors) = reactions.get(&msg.message_id) {
                for (emoji, author_user_id) in emoji_authors {
                    let author_label = username_by_user
                        .get(author_user_id)
                        .cloned()
                        .unwrap_or_else(|| short_user_label(author_user_id));
                    lines.push(format!("         {} {}", emoji, author_label));
                }
            }
            if let Some(file_rows) = files_by_message.get(&msg.message_id) {
                for file_row in file_rows {
                    let slices = file_slice::schema::list_for_file(
                        &context.store,
                        workspace_id,
                        file_row.file_id,
                    )?;
                    let slices_received = slices.len() as u32;
                    lines.push(format!(
                        "         {}",
                        format_file_display(
                            &file_row.filename,
                            file_row.blob_bytes,
                            file_row.total_slices,
                            slices_received,
                        )
                    ));
                }
            }
        }
    }

    Ok(CliOutput::lines(lines))
}

#[derive(Debug, Clone)]
struct ViewUser {
    user_id: EventId,
    username: String,
    device_name: String,
    is_local: bool,
}

fn workspace_user_view(
    store: &Store,
    workspace_id: EventId,
    local_endpoint_id: endpoint::types::EndpointId,
) -> Result<Vec<ViewUser>, String> {
    // Build a map of user rows so the view shows the latest known username per
    // user, then add one entry per endpoint_shared row so each device appears
    // on its own line. Endpoints whose user row has not yet projected fall
    // back to a short id label so the view still surfaces them.
    let mut usernames: BTreeMap<EventId, String> = BTreeMap::new();
    for (key, value) in store
        .table_rows_with_key_prefix(user::schema::USERS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load users: {err}"))?
    {
        let row = user::schema::decode_user_row(&key, &value)?;
        usernames.insert(row.user_id, row.username);
    }

    let mut shared_rows = Vec::new();
    for (key, value) in store
        .table_rows_with_key_prefix(
            endpoint_shared::schema::ENDPOINT_SHARED,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load endpoint_shared: {err}"))?
    {
        let row = endpoint_shared::schema::decode_endpoint_shared_row(&key, &value)?;
        shared_rows.push(row);
    }
    shared_rows.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.endpoint_shared_id.cmp(&b.endpoint_shared_id))
    });

    let mut out = Vec::with_capacity(shared_rows.len());
    for row in shared_rows {
        let user_id = row.user_authority_event_id;
        let username = usernames
            .get(&user_id)
            .cloned()
            .unwrap_or_else(|| short_user_label(&user_id));
        let is_local = row.endpoint_id == local_endpoint_id;
        out.push(ViewUser {
            user_id,
            username,
            device_name: row.device_name,
            is_local,
        });
    }
    Ok(out)
}

fn reactions_with_authors(
    store: &Store,
    workspace_id: EventId,
) -> Result<BTreeMap<EventId, Vec<(String, EventId)>>, String> {
    // Reuse the message-cli helper that opens sealed reaction rows alongside
    // cleartext rows; the visible set must match the `messages` listing.
    let rows = message::cli::visible_reaction_rows(store, workspace_id)?;
    let mut grouped: BTreeMap<EventId, Vec<(String, EventId)>> = BTreeMap::new();
    let mut seen: BTreeMap<EventId, std::collections::HashSet<(EventId, String)>> = BTreeMap::new();
    for row in rows {
        let entry = seen.entry(row.target_message_id).or_default();
        let key = (row.author_user_id, row.emoji.clone());
        if entry.insert(key) {
            grouped
                .entry(row.target_message_id)
                .or_default()
                .push((row.emoji, row.author_user_id));
        }
    }
    Ok(grouped)
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn format_age_ms(now_ms: u64, created_at_ms: u64) -> String {
    if created_at_ms > now_ms {
        return "just now".to_string();
    }
    let age_ms = now_ms - created_at_ms;
    let secs = age_ms / 1000;
    if secs < 60 {
        return format!("{}s ago", secs);
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{}m ago", mins);
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{}h ago", hours);
    }
    let days = hours / 24;
    format!("{}d ago", days)
}

fn format_byte_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_file_display(
    filename: &str,
    blob_bytes: u64,
    total_slices: u32,
    slices_received: u32,
) -> String {
    let complete = total_slices > 0 && slices_received >= total_slices;
    let status = if complete { "\u{2714}" } else { "\u{23f3}" };
    let size = format_byte_size(blob_bytes);
    if !complete && total_slices > 0 {
        let pct = (slices_received as f64 / total_slices as f64 * 100.0) as u32;
        format!("{status}  {filename} ({size}, {pct}%)")
    } else {
        format!("{status}  {filename} ({size})")
    }
}

fn short_user_label(id: &EventId) -> String {
    let hex = message::cli::hex_id(*id);
    let len = hex.len().min(8);
    hex[..len].to_string()
}
