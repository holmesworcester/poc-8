//! Projector for signed file slices.
//!
//! Each slice event names its descriptor by `file_event_id` and its parent
//! message's content key by `local_history_node_secret_id`, so the worker pulls the
//! descriptor into projection context and the local key-secret will be in
//! the dependency context too. The projector reads the sealed-blob
//! `root_hash` from the descriptor's clear-text fields, verifies the BAO
//! slice proof against that hash for the byte range
//! `[slice_number * (slice_bytes + tag) .. + plaintext_len + tag)` (clamped at
//! the file tail), and writes the verified ciphertext into the slot row.
//! Plaintext is never written; the read path opens each slice using the local
//! key-secret named by `local_history_node_secret_id`. Out-of-order arrival blocks
//! until the descriptor and the local key-secret apply, then admission
//! unblocks the slice.

use crate::protocol::event_modules::content::file;
use crate::protocol::event_modules::identity::{endpoint_shared, signed};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

const SLICE_TAG_BYTES: u64 = 16;

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let (slice, file_event_id) = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(slice.workspace_id) {
        return Err("file slice workspace metadata does not match event body".to_string());
    }

    let signer = event
        .context
        .dependency(&envelope.signer_endpoint_shared_id)
        .ok_or_else(|| "file slice signer endpoint_shared dependency is missing".to_string())?;
    let signer_envelope = signed::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "file slice signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err("file slice signer dependency is not a signed endpoint_shared".to_string());
    }
    let signer_endpoint_shared = endpoint_shared::codec::decode(&signer_envelope.payload)
        .map_err(|_| "file slice signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_endpoint_shared.workspace_id != slice.workspace_id {
        return Err("file slice signer endpoint_shared workspace does not match slice".to_string());
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err("file slice signer public key does not match endpoint_shared".to_string());
    }

    let descriptor = event
        .context
        .dependency(&file_event_id)
        .ok_or_else(|| "file slice file descriptor dependency is missing".to_string())?;
    let descriptor_envelope = file::codec::decode_signed(&descriptor.canonical_bytes)
        .map_err(|_| "file slice descriptor dependency is not a signed file".to_string())?;
    let descriptor_file = file::codec::decode(&descriptor_envelope.payload)
        .map_err(|_| "file slice descriptor dependency is not a signed file".to_string())?;
    if descriptor_file.workspace_id != slice.workspace_id {
        return Err("file slice descriptor workspace does not match slice".to_string());
    }
    if descriptor_file.file_id != slice.file_id {
        return Err("file slice descriptor file_id does not match slice".to_string());
    }
    if descriptor_file.local_history_node_secret_id != slice.local_history_node_secret_id {
        return Err(
            "file slice local key secret does not match descriptor local key secret".to_string(),
        );
    }
    if slice.slice_number >= descriptor_file.total_slices {
        return Err("file slice number is out of range for descriptor".to_string());
    }

    // Compute expected ciphertext layout: every full plaintext slice
    // contributes `slice_bytes + tag` ciphertext bytes; the tail slice's
    // plaintext is `blob_bytes - slice_number * slice_bytes`, padded by one
    // tag.
    let plaintext_per_full = u64::from(descriptor_file.slice_bytes);
    let chunk = plaintext_per_full + SLICE_TAG_BYTES;
    let slice_start = u64::from(slice.slice_number) * chunk;
    let total_ciphertext_len =
        descriptor_file.blob_bytes + u64::from(descriptor_file.total_slices) * SLICE_TAG_BYTES;

    let expected_plaintext_len = plaintext_per_full.min(
        descriptor_file
            .blob_bytes
            .saturating_sub(u64::from(slice.slice_number) * plaintext_per_full),
    );
    let expected_plaintext_len_u32 = u32::try_from(expected_plaintext_len)
        .map_err(|_| "file slice plaintext length overflows u32".to_string())?;
    if expected_plaintext_len_u32 != slice.plaintext_len {
        return Err(format!(
            "file slice plaintext_len {} does not match descriptor-derived expectation {}",
            slice.plaintext_len, expected_plaintext_len_u32
        ));
    }
    let slice_len = expected_plaintext_len + SLICE_TAG_BYTES;
    if slice_start.saturating_add(slice_len) > total_ciphertext_len {
        return Err("file slice extends past descriptor ciphertext bounds".to_string());
    }
    let verified_ciphertext = codec::verify_slice_proof(
        &descriptor_file.root_hash,
        &slice.proof,
        slice_start,
        slice_len,
    )
    .map_err(|err| format!("file slice bao verification failed: {err}"))?;

    Ok(ProjectionOutput::rows(vec![schema::file_slice_row(
        event.context.event_id,
        envelope.signer_endpoint_shared_id,
        &slice,
        verified_ciphertext,
    )?]))
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::{
        self, XChaCha20Poly1305Key, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES,
        XCHACHA20_POLY1305_TAG_BYTES,
    };
    use crate::protocol::event_modules::content::file;
    use crate::protocol::event_modules::identity::{endpoint_shared, signed};
    use crate::protocol::event_modules::types::{event_id, EventScope};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::FileSliceEvent;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    const KEY_SECRET: XChaCha20Poly1305Key = [77; 32];

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        let event = FileSliceEvent {
            workspace_id: [0; 32],
            created_at_ms: 0,
            file_id: [0; 32],
            slice_number: 0,
            local_history_node_secret_id: [0; 32],
            plaintext_len: 0,
            proof: Vec::new(),
        };
        let payload = codec::encode(&event, &[0; 32]).expect("encode for pubkey");
        codec::sign([0; 32], private_key, payload).signer_public_key
    }

    fn endpoint_shared_record(workspace_id: [u8; 32], signing_public_key: [u8; 32]) -> Record {
        let payload =
            endpoint_shared::codec::encode(&endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id: [50; 32],
                endpoint_id: [21; 32],
                signing_public_key,
                endpoint_role:
                    crate::protocol::event_modules::identity::endpoint::types::EndpointRole::Device,
                device_name: "laptop".to_string(),
            })
            .expect("encode endpoint_shared");
        let signed = signed::commands::sign_payload([6; 32], &[5; 32], payload)
            .expect("sign endpoint_shared");
        signed.events[0].record().clone()
    }

    #[allow(clippy::too_many_arguments)]
    fn descriptor_record(
        workspace_id: [u8; 32],
        file_id: [u8; 32],
        blob_bytes: u64,
        slice_bytes: u32,
        total_slices: u32,
        local_secret_id: [u8; 32],
        frontier_id: [u8; 32],
        descriptor_signer: [u8; 32],
        descriptor_signer_private: [u8; 32],
        root_hash: [u8; 32],
    ) -> Record {
        let descriptor_nonce: XChaCha20Poly1305Nonce = [9; XCHACHA20_POLY1305_NONCE_BYTES];
        let mut event = file::types::FileEvent {
            workspace_id,
            created_at_ms: 1,
            message_id: [70; 32],
            author_user_id: [71; 32],
            file_id,
            blob_bytes,
            total_slices,
            slice_bytes,
            root_hash,
            removal_frontier_id: frontier_id,
            local_history_node_secret_id: local_secret_id,
            nonce: descriptor_nonce,
            ciphertext: [0; file::types::FILE_DESCRIPTOR_CIPHERTEXT_BYTES],
        };
        let aad = file::codec::descriptor_associated_data(&event, descriptor_signer);
        event.ciphertext = file::codec::seal_descriptor_slot(
            &KEY_SECRET,
            &event.nonce,
            &aad,
            &file::types::FileDescriptorPlaintext {
                filename: "payload.bin".to_string(),
                mime_type: "application/octet-stream".to_string(),
            },
        )
        .expect("seal descriptor");
        let payload = file::codec::encode(&event).expect("encode file");
        let envelope = file::codec::sign(descriptor_signer, &descriptor_signer_private, payload);
        let bytes = file::codec::encode_signed(&envelope);
        file::codec::signed_record_from_bytes(bytes).expect("record")
    }

    struct BuiltSlice {
        record: Record,
        slice_event_id: [u8; 32],
        signer_id: [u8; 32],
        signer_record: Record,
        descriptor_id: [u8; 32],
        descriptor_record: Record,
        local_secret_id: [u8; 32],
        plaintext: Vec<u8>,
    }

    fn build_slice(slice_number: u32, slice_bytes: u32, total_slices: u32) -> BuiltSlice {
        let workspace_id = [7; 32];
        let frontier_id = [4; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let signer_record = endpoint_shared_record(workspace_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let file_id = [88; 32];
        let descriptor_signer = [99; 32];
        let descriptor_signer_private = [100; 32];
        let local_secret_id = [110; 32];

        let blob_total =
            (total_slices as usize - 1) * slice_bytes as usize + (slice_bytes as usize / 4 + 17);
        let plaintext: Vec<u8> = (0..blob_total).map(|byte| byte as u8).collect();

        // Slice AAD does not bind file_event_id, so seal once.
        let mut ciphertext_total =
            Vec::with_capacity(blob_total + (total_slices as usize) * XCHACHA20_POLY1305_TAG_BYTES);
        for k in 0..total_slices {
            let start = (k as usize) * slice_bytes as usize;
            let end = ((k + 1) as usize * slice_bytes as usize).min(plaintext.len());
            let slice_plain = &plaintext[start..end];
            let ciphertext = codec::seal_slice(
                &KEY_SECRET,
                &workspace_id,
                &file_id,
                k,
                &signer_id,
                slice_plain,
            )
            .expect("seal slice");
            ciphertext_total.extend_from_slice(&ciphertext);
        }
        let (root_hash, outboard) = crypto::bao_outboard(&ciphertext_total).expect("outboard");

        let descriptor = descriptor_record(
            workspace_id,
            file_id,
            blob_total as u64,
            slice_bytes,
            total_slices,
            local_secret_id,
            frontier_id,
            descriptor_signer,
            descriptor_signer_private,
            root_hash,
        );
        let descriptor_id = event_id(&descriptor.canonical_bytes);

        let slice_plaintext_len = ((slice_number + 1) as usize * slice_bytes as usize)
            .min(plaintext.len())
            - (slice_number as usize) * slice_bytes as usize;
        let chunk = slice_bytes as u64 + XCHACHA20_POLY1305_TAG_BYTES as u64;
        let slice_start = u64::from(slice_number) * chunk;
        let slice_len = slice_plaintext_len as u64 + XCHACHA20_POLY1305_TAG_BYTES as u64;
        let slice = codec::build_slice(super::super::types::BuildSlice {
            workspace_id,
            created_at_ms: 5,
            file_id,
            slice_number,
            local_history_node_secret_id: local_secret_id,
            plaintext_len: slice_plaintext_len as u32,
            ciphertext: &ciphertext_total,
            outboard: &outboard,
            slice_start,
            slice_len,
        })
        .expect("build slice");
        let payload = codec::encode(&slice, &descriptor_id).expect("encode");
        let envelope = codec::sign(signer_id, &signer_private_key, payload);
        let bytes = codec::encode_signed(&envelope);
        let slice_event_id = event_id(&bytes);
        let record = codec::signed_record_from_bytes(bytes).expect("record");

        BuiltSlice {
            record,
            slice_event_id,
            signer_id,
            signer_record,
            descriptor_id,
            descriptor_record: descriptor,
            local_secret_id,
            plaintext: plaintext[(slice_number as usize) * slice_bytes as usize
                ..(slice_number as usize) * slice_bytes as usize + slice_plaintext_len]
                .to_vec(),
        }
    }

    fn context_for<'a>(built: &'a BuiltSlice) -> EventWithContext<'a> {
        EventWithContext {
            record: &built.record,
            context: EventContext {
                event_id: built.slice_event_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: built.signer_id,
                        record: built.signer_record.clone(),
                    },
                    DependencyContext {
                        event_id: built.descriptor_id,
                        record: built.descriptor_record.clone(),
                    },
                ],
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        }
    }

    #[test]
    fn projects_one_slice_row_with_bao_verified_ciphertext() {
        let built = build_slice(0, 1024, 2);
        let event = context_for(&built);
        let output = project(&event).expect("project slice");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::FILE_SLICES);
        let row = schema::decode_file_slice_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, [7; 32]);
        assert_eq!(row.slice_number, 0);
        assert_eq!(row.slice_event_id, built.slice_event_id);
        assert_eq!(row.plaintext_len as usize, built.plaintext.len());
        assert_eq!(
            row.ciphertext.len(),
            built.plaintext.len() + XCHACHA20_POLY1305_TAG_BYTES
        );
        // Verified ciphertext must not contain plaintext bytes.
        // (The plaintext here is sequential bytes 0..N which is unlikely to
        // appear in random ciphertext, but we still check.)
        assert!(row.ciphertext != built.plaintext);
    }

    #[test]
    fn rejects_slice_whose_proof_does_not_match_descriptor_root_hash() {
        let mut built = build_slice(0, 1024, 1);
        let envelope = codec::decode_signed(&built.record.canonical_bytes).expect("decode signed");
        let (mut slice, descriptor_id) = codec::decode(&envelope.payload).expect("decode");
        slice.proof[0] ^= 1;
        let payload = codec::encode(&slice, &descriptor_id).expect("re-encode");
        let resigned = codec::sign(built.signer_id, &[9; 32], payload);
        let bytes = codec::encode_signed(&resigned);
        built.slice_event_id = crate::protocol::event_modules::types::event_id(&bytes);
        built.record = codec::signed_record_from_bytes(bytes).expect("record");

        let event = context_for(&built);
        let err = project(&event).expect_err("bad proof must fail");
        assert!(err.contains("bao verification failed"), "{err}");
    }

    #[test]
    fn rejects_slice_with_descriptor_local_key_secret_mismatch() {
        let built = build_slice(0, 1024, 1);
        // Construct a slice whose local_history_node_secret_id diverges from the
        // descriptor's. We do that by re-encoding the slice payload with a
        // tampered local_history_node_secret_id and re-signing.
        let envelope = codec::decode_signed(&built.record.canonical_bytes).expect("decode signed");
        let (mut slice, descriptor_id) = codec::decode(&envelope.payload).expect("decode");
        slice.local_history_node_secret_id = [200; 32];
        let payload = codec::encode(&slice, &descriptor_id).expect("re-encode");
        let resigned = codec::sign(built.signer_id, &[9; 32], payload);
        let bytes = codec::encode_signed(&resigned);
        let new_id = crate::protocol::event_modules::types::event_id(&bytes);
        let new_record = codec::signed_record_from_bytes(bytes).expect("record");
        let mut tampered = built;
        tampered.slice_event_id = new_id;
        tampered.record = new_record;

        let event = context_for(&tampered);
        assert_eq!(
            project(&event).expect_err("local_key mismatch must fail"),
            "file slice local key secret does not match descriptor local key secret"
        );
    }

    #[test]
    fn record_exposes_signer_workspace_file_event_and_local_key_dependencies() {
        let built = build_slice(0, 1024, 1);
        let record = &built.record;
        assert_eq!(
            record.dependencies,
            vec![
                built.signer_id,
                [7; 32],
                built.descriptor_id,
                built.local_secret_id,
            ]
        );
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn raw_file_slice_bytes_are_not_admissible() {
        let event = FileSliceEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            file_id: [88; 32],
            slice_number: 0,
            local_history_node_secret_id: [4; 32],
            plaintext_len: 0,
            proof: Vec::new(),
        };
        let payload = codec::encode(&event, &[12; 32]).expect("encode");
        assert_eq!(
            crate::protocol::event_modules::record_from_bytes(payload)
                .expect_err("raw slice must fail"),
            "file slice must be signed"
        );
    }
}
