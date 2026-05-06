//! File leaf CLI: `files`, `save-file`.
//!
//! Read-only listing and assembly. The `send-file` write path lives at the
//! content domain root because it spans message + file + file_slice. This
//! file does not create canonical events; it consumes projected sealed
//! descriptor and slice rows for operator-facing reads, opening sealed slots
//! using the local key-secret named by the descriptor's `local_key_secret_id`
//! to recover plaintext filename, mime, and slice bytes.

use std::fs;
use std::path::PathBuf;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::store::Store;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::{file_slice, message};
use crate::protocol::event_modules::encryption::local_key_secret;
use crate::protocol::event_modules::types::EventId;

use super::codec;
use super::schema;
use super::types::{FileRow, SealedFileRow};

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
    /// Match poc-7's `FileRow.complete` rule: a file is complete when the
    /// descriptor declares at least one slice and every declared slice has
    /// been received. Zero-slice descriptors never go complete.
    pub fn is_complete(&self) -> bool {
        self.total_slices > 0 && self.slices_received >= self.total_slices
    }

    /// One row of the `files` listing, matching poc-7's display:
    ///
    /// ```text
    ///   1. ✔  filename (21 B)
    ///   2. ⌛  big.bin (1.23 MiB, 37%)
    ///   3. ⌛  unknown.bin (4.56 MiB)
    /// ```
    ///
    /// Detail lines (`mime`, `id`, `file_id`, `message`) follow the row line,
    /// indented to match the visual nesting.
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        let status = if self.is_complete() {
            "\u{2714}"
        } else {
            "\u{23f3}"
        };
        let size = format_byte_size(self.blob_bytes);
        let row = if self.is_complete() {
            format!("  {}. {}  {} ({})", self.index, status, self.filename, size)
        } else if self.total_slices > 0 {
            let pct = (f64::from(self.slices_received) / f64::from(self.total_slices) * 100.0)
                as u32;
            format!(
                "  {}. {}  {} ({}, {}%)",
                self.index, status, self.filename, size, pct
            )
        } else {
            format!("  {}. {}  {} ({})", self.index, status, self.filename, size)
        };
        out.push(row);
        out.push(format!("       mime: {}", self.mime_type));
        out.push(format!(
            "       id: {}",
            message::cli::hex_id(self.file_event_id)
        ));
        out.push(format!(
            "       file_id: {}",
            message::cli::hex_id(self.file_id)
        ));
        out.push(format!(
            "       message: {}",
            message::cli::hex_id(self.message_id)
        ));
        out
    }
}

/// Human-readable byte sizes matching poc-7's `format_byte_size`: `B`/`KiB`/
/// `MiB`/`GiB` with one decimal at and above KiB. Display-only.
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
        format!("{bytes} B")
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
    // poc-7 prints `FILES (N total):` followed by a blank line, then one row
    // per file.
    let mut lines = vec![
        format!("FILES ({} total):", summaries.len()),
        String::new(),
    ];
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

    let sealed = schema::sealed_file_row_by_id(&context.store, workspace_id, file_event_id)?
        .ok_or_else(|| "file does not exist".to_string())?;
    if message::cli::is_deleted_by_author(
        &context.store,
        &sealed.message_id,
        &sealed.author_user_id,
    )? {
        return Err("file does not exist".to_string());
    }
    let row = open_sealed_file_row(&context.store, &sealed)?
        .ok_or_else(|| "file local content key is missing; cannot decode".to_string())?;
    let slices = file_slice::schema::list_for_file(&context.store, workspace_id, row.file_id)?;
    if slices.len() < row.total_slices as usize {
        return Err(format!(
            "file incomplete: have {}/{} slices",
            slices.len(),
            row.total_slices
        ));
    }

    let secret = local_key_secret::schema::get(
        &context.store,
        sealed.workspace_id,
        sealed.removal_frontier_id,
    )?
    .ok_or_else(|| "local content key is missing".to_string())?;
    if secret.local_key_secret_id != sealed.local_key_secret_id {
        return Err("file local key secret id mismatch".to_string());
    }

    let mut bytes = Vec::with_capacity(row.blob_bytes as usize);
    for slice in &slices {
        let plaintext = file_slice::codec::open_slice(
            &secret.key_secret,
            &row.workspace_id,
            &row.file_id,
            slice.slice_number,
            slice.plaintext_len,
            &slice.signer_endpoint_shared_id,
            &slice.ciphertext,
        )
        .map_err(|err| format!("decode slice {}: {err}", slice.slice_number))?;
        bytes.extend_from_slice(&plaintext);
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
        let bytes_received: u64 = slices.iter().map(|slice| slice.plaintext_len as u64).sum();
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

pub(crate) fn visible_file_rows(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<FileRow>, String> {
    let sealed_rows = schema::list_sealed_for_workspace(store, workspace_id)?;
    let mut out = Vec::with_capacity(sealed_rows.len());
    for sealed in sealed_rows {
        if message::cli::is_deleted_by_author(
            store,
            &sealed.message_id,
            &sealed.author_user_id,
        )? {
            continue;
        }
        let Some(row) = open_sealed_file_row(store, &sealed)? else {
            continue;
        };
        out.push(row);
    }
    Ok(out)
}

pub(crate) fn open_sealed_file_row(
    store: &Store,
    sealed: &SealedFileRow,
) -> Result<Option<FileRow>, String> {
    let Some(secret) = local_key_secret::schema::get(
        store,
        sealed.workspace_id,
        sealed.removal_frontier_id,
    )?
    else {
        return Ok(None);
    };
    if secret.local_key_secret_id != sealed.local_key_secret_id {
        return Err("file local key secret id mismatch".to_string());
    }
    let event = super::types::FileEvent {
        workspace_id: sealed.workspace_id,
        created_at_ms: sealed.created_at_ms,
        message_id: sealed.message_id,
        author_user_id: sealed.author_user_id,
        file_id: sealed.file_id,
        blob_bytes: sealed.blob_bytes,
        total_slices: sealed.total_slices,
        slice_bytes: sealed.slice_bytes,
        root_hash: sealed.root_hash,
        removal_frontier_id: sealed.removal_frontier_id,
        local_key_secret_id: sealed.local_key_secret_id,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    };
    let aad = codec::descriptor_associated_data(&event, sealed.signer_endpoint_shared_id);
    let plaintext = codec::open_descriptor_slot(
        &secret.key_secret,
        &sealed.nonce,
        &aad,
        &sealed.ciphertext,
    )
    .map_err(|err| format!("decode file descriptor: {err}"))?;
    Ok(Some(FileRow {
        workspace_id: sealed.workspace_id,
        file_event_id: sealed.file_event_id,
        message_id: sealed.message_id,
        file_id: sealed.file_id,
        author_user_id: sealed.author_user_id,
        signer_endpoint_shared_id: sealed.signer_endpoint_shared_id,
        created_at_ms: sealed.created_at_ms,
        blob_bytes: sealed.blob_bytes,
        total_slices: sealed.total_slices,
        slice_bytes: sealed.slice_bytes,
        root_hash: sealed.root_hash,
        removal_frontier_id: sealed.removal_frontier_id,
        local_key_secret_id: sealed.local_key_secret_id,
        filename: plaintext.filename,
        mime_type: plaintext.mime_type,
    }))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_summary(
        index: usize,
        filename: &str,
        blob_bytes: u64,
        total_slices: u32,
        slices_received: u32,
        bytes_received: u64,
    ) -> FileSummary {
        FileSummary {
            index,
            file_event_id: [0u8; 32],
            file_id: [0u8; 32],
            message_id: [0u8; 32],
            filename: filename.to_string(),
            mime_type: "application/octet-stream".to_string(),
            blob_bytes,
            total_slices,
            slices_received,
            bytes_received,
        }
    }

    #[test]
    fn complete_file_summary_renders_check_mark_and_human_size() {
        let summary = fixed_summary(1, "payload.txt", 21, 1, 1, 21);
        assert!(summary.is_complete());
        let lines = summary.lines();
        assert_eq!(lines[0], "  1. \u{2714}  payload.txt (21 B)");
    }

    #[test]
    fn partial_file_summary_renders_hourglass_and_percent() {
        let summary = fixed_summary(2, "big.bin", 1_290_000, 8, 3, 393_216);
        assert!(!summary.is_complete());
        let lines = summary.lines();
        // 3/8 -> 37%; 1_290_000 bytes -> 1.2 MiB.
        assert_eq!(lines[0], "  2. \u{23f3}  big.bin (1.2 MiB, 37%)");
    }

    #[test]
    fn zero_progress_descriptor_renders_hourglass_with_percent_zero() {
        let summary = fixed_summary(3, "fresh.bin", 4 * 1024 * 1024, 16, 0, 0);
        assert!(!summary.is_complete());
        let lines = summary.lines();
        assert_eq!(lines[0], "  3. \u{23f3}  fresh.bin (4.0 MiB, 0%)");
    }

    #[test]
    fn zero_slice_descriptor_renders_hourglass_without_percent() {
        // total_slices == 0 is a degenerate descriptor; poc-7 omits the
        // percentage suffix in that case so we never divide by zero.
        let summary = fixed_summary(4, "unknown.bin", 1024, 0, 0, 0);
        assert!(!summary.is_complete());
        let lines = summary.lines();
        assert_eq!(lines[0], "  4. \u{23f3}  unknown.bin (1.0 KiB)");
    }

    #[test]
    fn format_byte_size_matches_poc_7() {
        assert_eq!(format_byte_size(0), "0 B");
        assert_eq!(format_byte_size(1023), "1023 B");
        assert_eq!(format_byte_size(1024), "1.0 KiB");
        assert_eq!(format_byte_size(1024 * 1024), "1.0 MiB");
        assert_eq!(format_byte_size(1024 * 1024 * 1024), "1.0 GiB");
    }
}
