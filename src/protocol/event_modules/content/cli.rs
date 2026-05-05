//! Content domain CLI for cross-module flows.
//!
//! `send-file` is the canonical cross-module command: it creates one message
//! event, one file descriptor event, and N file_slice events in a single
//! bundle. Leaf-module CLI files own per-event commands; this file is reserved
//! for flows that can only be described as a join over multiple children.

use std::fs;
use std::path::PathBuf;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::crypto;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::{file, file_slice, message};
use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{self, CommandOutput, ProposedEvent};

const SEND_FILE_USAGE: &str = "send-file WORKSPACE_ID_HEX TEXT --file PATH [--mime MIME]";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "send-file",
        usage: SEND_FILE_USAGE,
        help: "Send a message with an attached file from disk.",
        run: run_send_file_command,
    }]
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
            format!("file_event_id: {}", message::cli::hex_id(self.file_event_id)),
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

    let bytes = fs::read(&parsed.file_path)
        .map_err(|err| format!("read {}: {err}", parsed.file_path.display()))?;
    let blob_bytes = bytes.len() as u64;
    let slice_bytes = u32::try_from(file_slice::types::FILE_SLICE_DATA_BYTES)
        .map_err(|_| "slice budget overflows u32".to_string())?;
    let total_slices = if blob_bytes == 0 {
        0
    } else {
        u32::try_from(bytes.len().div_ceil(file_slice::types::FILE_SLICE_DATA_BYTES))
            .map_err(|_| "slice count overflows u32".to_string())?
    };
    let filename = parsed
        .file_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "file path is not valid utf-8".to_string())?
        .to_string();

    let (root_hash, outboard) = crypto::bao_outboard(&bytes)?;

    let starting_timestamp = message::cli::next_timestamp(&context.store, parsed.workspace_id)?;
    let mut timestamp = starting_timestamp;

    let send = message::commands::send(message::commands::SendMessage {
        workspace_id: parsed.workspace_id,
        created_at_ms: timestamp,
        author_user_id: membership.user_authority_event_id,
        signer_endpoint_shared_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
        text: parsed.text,
    })?;
    let message_id = send.value.message_id;
    timestamp = timestamp.saturating_add(1);

    let file_id = derive_file_id(&membership.endpoint_shared_id, message_id, starting_timestamp);
    let create_file = file::commands::create(file::commands::CreateFile {
        workspace_id: parsed.workspace_id,
        created_at_ms: timestamp,
        message_id,
        author_user_id: membership.user_authority_event_id,
        signer_endpoint_shared_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
        file_id,
        blob_bytes,
        total_slices,
        slice_bytes,
        root_hash,
        filename: filename.clone(),
        mime_type: parsed.mime_type.clone(),
    })?;
    timestamp = timestamp.saturating_add(1);

    let mut bundled: Vec<ProposedEvent> = Vec::new();
    bundled.extend(send.events);
    let file_event_id = create_file.value.file_event_id;
    bundled.extend(create_file.events);

    for slice_number in 0..total_slices {
        let start = u64::from(slice_number) * u64::from(slice_bytes);
        let len = u64::from(slice_bytes).min(blob_bytes - start);
        let slice =
            file_slice::commands::slice_from_plaintext(file_slice::commands::SliceFromPlaintext {
                workspace_id: parsed.workspace_id,
                created_at_ms: timestamp,
                file_id,
                file_event_id,
                slice_number,
                signer_endpoint_shared_id: membership.endpoint_shared_id,
                signer_private_key: local.signing_secret,
                plaintext: &bytes,
                outboard: &outboard,
                slice_start: start,
                slice_len: len,
            })?;
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
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"poc8-content-file-id\0");
    hasher.update(signer_endpoint_shared_id);
    hasher.update(&message_id);
    hasher.update(&starting_timestamp.to_be_bytes());
    *hasher.finalize().as_bytes()
}
