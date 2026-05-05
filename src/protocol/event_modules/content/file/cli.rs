//! File leaf CLI: `files`, `save-file`.
//!
//! Read-only listing and assembly. The `send-file` write path lives at the
//! content domain root because it spans message + file + file_slice.

use std::fs;
use std::path::PathBuf;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::store::Store;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::{file_slice, message};
use crate::protocol::event_modules::types::EventId;

use super::schema;

const FILES_USAGE: &str = "files WORKSPACE_ID_HEX [LIMIT]";
const SAVE_FILE_USAGE: &str = "save-file WORKSPACE_ID_HEX FILE_SELECTOR OUT_PATH";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "files",
            usage: FILES_USAGE,
            help: "List files attached in a workspace.",
            run: run_files_command,
        },
        CliCommand {
            name: "save-file",
            usage: SAVE_FILE_USAGE,
            help: "Save the bytes of a file from a workspace to a path.",
            run: run_save_file_command,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSummary {
    pub index: usize,
    pub file_event_id: EventId,
    pub file_id: EventId,
    pub message_id: EventId,
    pub filename: String,
    pub mime_type: String,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slices_received: u32,
    pub bytes_received: u64,
}

impl FileSummary {
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.push(format!(
            "{}. {} ({}/{} slices, {} of {} bytes)",
            self.index,
            self.filename,
            self.slices_received,
            self.total_slices,
            self.bytes_received,
            self.blob_bytes
        ));
        out.push(format!("   mime: {}", self.mime_type));
        out.push(format!(
            "   id: {}",
            message::cli::hex_id(self.file_event_id)
        ));
        out.push(format!(
            "   file_id: {}",
            message::cli::hex_id(self.file_id)
        ));
        out.push(format!(
            "   message: {}",
            message::cli::hex_id(self.message_id)
        ));
        out
    }
}

fn run_files_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    if args.values().is_empty() || args.values().len() > 2 {
        return Err(FILES_USAGE.to_string());
    }
    let workspace_id =
        message::cli::parse_hex_id(args.get(0).expect("length checked"), FILES_USAGE)?;
    let limit = match args.get(1) {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| FILES_USAGE.to_string())?,
        None => 0,
    };
    let summaries = list_summaries(&context.store, workspace_id, limit)?;
    let mut lines = vec![format!("files: {}", summaries.len())];
    for summary in &summaries {
        lines.extend(summary.lines());
    }
    Ok(CliOutput::lines(lines))
}

fn run_save_file_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(3, SAVE_FILE_USAGE)?;
    let workspace_id =
        message::cli::parse_hex_id(args.get(0).expect("length checked"), SAVE_FILE_USAGE)?;
    let file_event_id = resolve_file_selector(
        &context.store,
        workspace_id,
        args.get(1).expect("length checked"),
    )?;
    let out_path = PathBuf::from(args.get(2).expect("length checked"));

    let row = schema::file_row_by_id(&context.store, workspace_id, file_event_id)?
        .ok_or_else(|| "file does not exist".to_string())?;
    if message::cli::is_deleted_by_author(&context.store, &row.message_id, &row.author_user_id)? {
        return Err("file does not exist".to_string());
    }
    let slices = file_slice::schema::list_for_file(&context.store, workspace_id, row.file_id)?;
    if slices.len() < row.total_slices as usize {
        return Err(format!(
            "file is incomplete: {} of {} slices received",
            slices.len(),
            row.total_slices
        ));
    }

    let mut bytes = Vec::with_capacity(row.blob_bytes as usize);
    for slice in &slices {
        bytes.extend_from_slice(&slice.data);
    }
    if bytes.len() as u64 != row.blob_bytes {
        return Err(format!(
            "assembled file bytes ({}) do not match blob_bytes ({})",
            bytes.len(),
            row.blob_bytes
        ));
    }
    fs::write(&out_path, &bytes).map_err(|err| format!("write {}: {err}", out_path.display()))?;

    Ok(CliOutput::lines(vec![
        format!("file_event_id: {}", message::cli::hex_id(file_event_id)),
        format!("filename: {}", row.filename),
        format!("output_path: {}", out_path.display()),
        format!("bytes_written: {}", bytes.len()),
        format!("total_slices: {}", row.total_slices),
    ]))
}

pub fn list_summaries(
    store: &Store,
    workspace_id: EventId,
    limit: usize,
) -> Result<Vec<FileSummary>, String> {
    let mut rows = visible_file_rows(store, workspace_id)?;
    let total = rows.len();
    let take = if limit == 0 || limit >= total {
        total
    } else {
        limit
    };
    let start = total - take;
    rows.drain(..start);
    let mut summaries = Vec::with_capacity(rows.len());
    for (idx, row) in rows.into_iter().enumerate() {
        let slices = file_slice::schema::list_for_file(store, workspace_id, row.file_id)?;
        let slices_received = u32::try_from(slices.len()).unwrap_or(u32::MAX);
        let bytes_received: u64 = slices.iter().map(|slice| slice.data.len() as u64).sum();
        summaries.push(FileSummary {
            index: start + idx + 1,
            file_event_id: row.file_event_id,
            file_id: row.file_id,
            message_id: row.message_id,
            filename: row.filename.clone(),
            mime_type: row.mime_type.clone(),
            blob_bytes: row.blob_bytes,
            total_slices: row.total_slices,
            slices_received,
            bytes_received,
        });
    }
    Ok(summaries)
}

fn visible_file_rows(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<super::types::FileRow>, String> {
    schema::list_for_workspace(store, workspace_id)?
        .into_iter()
        .filter_map(|row| {
            match message::cli::is_deleted_by_author(store, &row.message_id, &row.author_user_id) {
                Ok(false) => Some(Ok(row)),
                Ok(true) => None,
                Err(err) => Some(Err(err)),
            }
        })
        .collect()
}

fn resolve_file_selector(
    store: &Store,
    workspace_id: EventId,
    selector: &str,
) -> Result<EventId, String> {
    if let Some(rest) = selector.strip_prefix('#') {
        let number: usize = rest
            .parse()
            .map_err(|_| format!("invalid file selector: {selector}"))?;
        if number == 0 {
            return Err(format!("invalid file selector: {selector}"));
        }
        let rows = visible_file_rows(store, workspace_id)?;
        let row = rows
            .get(number - 1)
            .ok_or_else(|| format!("file #{number} does not exist"))?;
        Ok(row.file_event_id)
    } else {
        message::cli::parse_hex_id(selector, "FILE_SELECTOR")
    }
}
