//! Projector for signed file slices.
//!
//! Each slice event names its descriptor by `file_event_id`, so the worker
//! pulls the descriptor into projection context. The projector verifies the
//! BAO slice proof against `descriptor.root_hash` for the byte range
//! `[slice_number * slice_bytes .. + slice_len)` (where `slice_len` is the
//! descriptor's per-slice budget, clamped at the file tail), and writes the
//! verified plaintext into the slot row. Out-of-order arrival just blocks
//! until the descriptor applies; admission then unblocks the slice.

use crate::core::bao_verify_slice;
use crate::protocol::event_modules::content::file;
use crate::protocol::event_modules::identity::{endpoint_shared, signed};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

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
    if slice.slice_number >= descriptor_file.total_slices {
        return Err("file slice number is out of range for descriptor".to_string());
    }

    let slice_start = u64::from(slice.slice_number) * u64::from(descriptor_file.slice_bytes);
    let slice_len = u64::from(descriptor_file.slice_bytes)
        .min(descriptor_file.blob_bytes.saturating_sub(slice_start));
    let verified = bao_verify_slice(
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
        verified,
    )]))
}

#[cfg(test)]
mod tests {
    use crate::core::bao_outboard;
    use crate::protocol::event_modules::content::file;
    use crate::protocol::event_modules::identity::{endpoint_shared, signed};
    use crate::protocol::event_modules::types::{event_id, EventScope};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::FileSliceEvent;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        let event = FileSliceEvent {
            workspace_id: [0; 32],
            created_at_ms: 0,
            file_id: [0; 32],
            slice_number: 0,
            proof: Vec::new(),
        };
        let payload = codec::encode(&event, &[0; 32]).expect("encode for pubkey");
        codec::sign([0; 32], private_key, payload).signer_public_key
    }

    fn endpoint_shared_record(workspace_id: [u8; 32], signing_public_key: [u8; 32]) -> Record {
        let payload = endpoint_shared::codec::encode(&endpoint_shared::types::EndpointSharedEvent {
            created_at_ms: 4,
            workspace_id,
            user_authority_event_id: [50; 32],
            endpoint_id: [21; 32],
            signing_public_key,
            device_name: "laptop".to_string(),
        })
        .expect("encode endpoint_shared");
        let signed = signed::commands::sign_payload([6; 32], &[5; 32], payload)
            .expect("sign endpoint_shared");
        signed.events[0].record().clone()
    }

    fn descriptor_record(
        workspace_id: [u8; 32],
        file_id: [u8; 32],
        blob_bytes: u64,
        slice_bytes: u32,
        total_slices: u32,
        root_hash: [u8; 32],
    ) -> Record {
        let payload = file::codec::encode(&file::types::FileEvent {
            workspace_id,
            created_at_ms: 1,
            message_id: [70; 32],
            author_user_id: [71; 32],
            file_id,
            blob_bytes,
            total_slices,
            slice_bytes,
            root_hash,
            filename: "payload.bin".to_string(),
            mime_type: "application/octet-stream".to_string(),
        })
        .expect("encode file");
        let envelope = file::codec::sign([72; 32], &[73; 32], payload);
        let bytes = file::codec::encode_signed(&envelope);
        file::codec::signed_record_from_bytes(bytes).expect("record")
    }

    #[test]
    fn projects_one_slice_row_with_bao_verified_plaintext() {
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let signer_record = endpoint_shared_record(workspace_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let file_id = [88; 32];
        let plaintext: Vec<u8> = (0..2048u32).map(|byte| byte as u8).collect();
        let (root_hash, outboard) = bao_outboard(&plaintext).expect("outboard");

        let descriptor = descriptor_record(
            workspace_id,
            file_id,
            plaintext.len() as u64,
            1024,
            2,
            root_hash,
        );
        let descriptor_id = event_id(&descriptor.canonical_bytes);

        let slice = codec::build_slice(super::super::types::BuildSlice {
            workspace_id,
            created_at_ms: 5,
            file_id,
            slice_number: 0,
            plaintext: &plaintext,
            outboard: &outboard,
            slice_start: 0,
            slice_len: 1024,
        })
        .expect("build slice");
        let payload = codec::encode(&slice, &descriptor_id).expect("encode");
        let envelope = codec::sign(signer_id, &signer_private_key, payload);
        let bytes = codec::encode_signed(&envelope);
        let slice_event_id = event_id(&bytes);
        let record = codec::signed_record_from_bytes(bytes).expect("record");

        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: slice_event_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: signer_id,
                        record: signer_record,
                    },
                    DependencyContext {
                        event_id: descriptor_id,
                        record: descriptor,
                    },
                ],
                labels: Vec::new(),
                receive: None,
            },
        };
        let output = project(&event).expect("project slice");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::FILE_SLICES);
        let row = schema::decode_file_slice_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, workspace_id);
        assert_eq!(row.file_id, file_id);
        assert_eq!(row.slice_number, 0);
        assert_eq!(row.slice_event_id, slice_event_id);
        assert_eq!(row.data, plaintext[..1024]);
    }

    #[test]
    fn rejects_slice_whose_proof_does_not_match_descriptor_root_hash() {
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let signer_record = endpoint_shared_record(workspace_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let file_id = [88; 32];

        let plaintext: Vec<u8> = (0..1024u32).map(|byte| byte as u8).collect();
        let (_real_root, outboard) = bao_outboard(&plaintext).expect("outboard");
        let descriptor = descriptor_record(
            workspace_id,
            file_id,
            plaintext.len() as u64,
            1024,
            1,
            [0xff; 32],
        );
        let descriptor_id = event_id(&descriptor.canonical_bytes);

        let slice = codec::build_slice(super::super::types::BuildSlice {
            workspace_id,
            created_at_ms: 5,
            file_id,
            slice_number: 0,
            plaintext: &plaintext,
            outboard: &outboard,
            slice_start: 0,
            slice_len: plaintext.len() as u64,
        })
        .expect("build slice");
        let payload = codec::encode(&slice, &descriptor_id).expect("encode");
        let envelope = codec::sign(signer_id, &signer_private_key, payload);
        let bytes = codec::encode_signed(&envelope);
        let slice_event_id = event_id(&bytes);
        let record = codec::signed_record_from_bytes(bytes).expect("record");

        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: slice_event_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: signer_id,
                        record: signer_record,
                    },
                    DependencyContext {
                        event_id: descriptor_id,
                        record: descriptor,
                    },
                ],
                labels: Vec::new(),
                receive: None,
            },
        };

        let err = project(&event).expect_err("bad root hash must fail");
        assert!(
            err.contains("bao verification failed"),
            "{err}"
        );
    }

    #[test]
    fn record_exposes_signer_workspace_and_file_event_id_dependencies() {
        let event = FileSliceEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            file_id: [88; 32],
            slice_number: 0,
            proof: Vec::new(),
        };
        let payload = codec::encode(&event, &[12; 32]).expect("encode");
        let envelope = codec::sign([10; 32], &[11; 32], payload);
        let bytes = codec::encode_signed(&envelope);
        let record = codec::signed_record_from_bytes(bytes).expect("record");
        assert_eq!(record.dependencies, vec![[10; 32], [7; 32], [12; 32]]);
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn raw_file_slice_bytes_are_not_admissible() {
        let event = FileSliceEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            file_id: [88; 32],
            slice_number: 0,
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
