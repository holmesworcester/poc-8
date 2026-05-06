//! Commands for creating file slices.
//!
//! `create` takes a pre-built BAO slice proof, the descriptor's event id, and
//! the descriptor's `local_key_secret_id`. `slice_from_ciphertext` is the
//! convenience wrapper send-file uses with the full encrypted blob and its
//! BAO outboard already in hand. Both produce one signed file slice event
//! whose projection verifies the slice's ciphertext bytes against the
//! descriptor's `root_hash`.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::{BuildSlice, FileSliceEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFileSlice {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub file_id: EventId,
    pub file_event_id: EventId,
    pub slice_number: u32,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub local_key_secret_id: EventId,
    pub plaintext_len: u32,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFileSliceOutput {
    pub slice_event_id: EventId,
    pub file_id: EventId,
    pub slice_number: u32,
}

pub fn create(input: CreateFileSlice) -> Result<CommandOutput<CreateFileSliceOutput>, String> {
    let event = FileSliceEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        file_id: input.file_id,
        slice_number: input.slice_number,
        local_key_secret_id: input.local_key_secret_id,
        plaintext_len: input.plaintext_len,
        proof: input.proof,
    };
    let payload = codec::encode(&event, &input.file_event_id)?;
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes_signed = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes_signed)?;
    let slice_event_id = crate::protocol::event_modules::types::event_id(&record.canonical_bytes);
    Ok(CommandOutput::with_events(
        CreateFileSliceOutput {
            slice_event_id,
            file_id: event.file_id,
            slice_number: event.slice_number,
        },
        vec![record],
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceFromCiphertext<'a> {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub file_id: EventId,
    pub file_event_id: EventId,
    pub slice_number: u32,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub local_key_secret_id: EventId,
    pub plaintext_len: u32,
    /// Concatenated per-slice ciphertexts; this is the byte stream BAO is
    /// computed over, so any slice proof verifies against the descriptor's
    /// encrypted-blob root hash.
    pub ciphertext: &'a [u8],
    pub outboard: &'a [u8],
    pub slice_start: u64,
    pub slice_len: u64,
}

pub fn slice_from_ciphertext(
    input: SliceFromCiphertext<'_>,
) -> Result<CommandOutput<CreateFileSliceOutput>, String> {
    let event = codec::build_slice(BuildSlice {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        file_id: input.file_id,
        slice_number: input.slice_number,
        local_key_secret_id: input.local_key_secret_id,
        plaintext_len: input.plaintext_len,
        ciphertext: input.ciphertext,
        outboard: input.outboard,
        slice_start: input.slice_start,
        slice_len: input.slice_len,
    })?;
    create(CreateFileSlice {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        file_id: input.file_id,
        file_event_id: input.file_event_id,
        slice_number: input.slice_number,
        signer_endpoint_shared_id: input.signer_endpoint_shared_id,
        signer_private_key: input.signer_private_key,
        local_key_secret_id: input.local_key_secret_id,
        plaintext_len: input.plaintext_len,
        proof: event.proof,
    })
}
