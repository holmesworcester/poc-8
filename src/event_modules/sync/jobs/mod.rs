pub mod queries;
pub mod tables;
pub mod types;

use ::negentropy::{Id, Negentropy};

use crate::event_modules::connection::outbox;
use crate::store::{event_id, Store, TableRowDeletion, WorkClaim, WorkRecord};

use self::types::{SyncJobOutput, SyncWork};
use super::compare::queries::ReadContext;
use super::compare::types::CompareEvent;
use super::data::types::DataEvent;
use super::frame::codec as frame_codec;
use super::frame::types::{Frame, SyncItem};
use super::need_id::types::NeedIdEvent;
use super::negentropy;

const INDEX_BATCH: usize = 4096;
const FRAME_TARGET_BYTES: usize = 32 * 1024 * 1024;
const FRAME_HEADER_BYTES: usize = 14;
const DATA_ITEM_HEADER_BYTES: usize = 1 + 32 + 4;
const DATA_ENTRY_BYTES: usize = 4;

pub fn queue_start(connection_id: crate::store::EventId, required_index_seq: u64) -> WorkRecord {
    types::start_record(connection_id, required_index_seq)
}

pub fn queue_inbound_frame(
    connection_id: crate::store::EventId,
    required_index_seq: u64,
    frame_bytes: Vec<u8>,
) -> WorkRecord {
    types::inbound_frame_record(connection_id, required_index_seq, frame_bytes)
}

pub fn catch_up_index(store: &Store) -> Result<Option<SyncJobOutput>, String> {
    catch_up_index_output(store)
}

pub fn run_claim(store: &Store, claim: &WorkClaim) -> Result<SyncJobOutput, String> {
    let work = types::decode(&claim.kind, &claim.payload)?;
    let cursor = negentropy::queries::cursor(store)?;
    if cursor < work.required_index_seq() {
        return Err(format!(
            "sync work requires index seq {}, cursor is {cursor}",
            work.required_index_seq()
        ));
    }
    run_work(store, work)
}

fn catch_up_index_output(store: &Store) -> Result<Option<SyncJobOutput>, String> {
    let cursor = negentropy::queries::cursor(store)?;
    let entries = store
        .applied_shared_entries_after(cursor, INDEX_BATCH)
        .map_err(|err| format!("load applied events for sync index: {err}"))?;
    let Some(last) = entries.last() else {
        return Ok(None);
    };

    let (cursor_delete, cursor_row) = negentropy::queries::cursor_update(last.apply_seq);
    let mut rows = negentropy::queries::index_rows(&entries);
    rows.push(cursor_row);
    Ok(Some(SyncJobOutput {
        rows,
        deleted_rows: vec![cursor_delete],
        ..SyncJobOutput::default()
    }))
}

fn run_work(store: &Store, work: SyncWork) -> Result<SyncJobOutput, String> {
    match work {
        SyncWork::Start { connection_id, .. } => start_sync(store, connection_id),
        SyncWork::InboundFrame {
            connection_id,
            frame_bytes,
            ..
        } => ingest_frame(store, connection_id, &frame_bytes),
    }
}

fn start_sync(
    store: &Store,
    connection_id: crate::store::EventId,
) -> Result<SyncJobOutput, String> {
    let storage = store.storage()?;
    let mut negentropy =
        Negentropy::borrowed(&storage, 0).map_err(|err| format!("start negentropy: {err:?}"))?;
    let message = negentropy
        .initiate()
        .map_err(|err| format!("initiate negentropy: {err:?}"))?;
    let frame = frame_codec::encode(&Frame {
        more: false,
        items: vec![SyncItem::Compare(CompareEvent {
            connection_id,
            message,
        })],
    });
    Ok(SyncJobOutput {
        rows: vec![
            queries::initiator_session_row(connection_id),
            outbox::projector::queue(connection_id, event_id(&frame), frame),
        ],
        ..SyncJobOutput::default()
    })
}

fn ingest_frame(
    store: &Store,
    expected_connection_id: crate::store::EventId,
    bytes: &[u8],
) -> Result<SyncJobOutput, String> {
    let frame = frame_codec::decode(bytes)?;
    let mut frame_connection_id = None;
    let mut response_items = Vec::new();
    let mut requested_ids = Vec::new();
    let mut received_event_bytes = Vec::new();
    let mut deleted_rows = Vec::new();

    for item in frame.items {
        match item {
            SyncItem::Compare(event) => {
                observe_connection(&mut frame_connection_id, event.connection_id)?;
                handle_compare(
                    store,
                    event,
                    &mut response_items,
                    &mut requested_ids,
                    &mut deleted_rows,
                )?;
            }
            SyncItem::HaveId(event) => {
                observe_connection(&mut frame_connection_id, event.connection_id)?;
                if !store
                    .has_event(&event.id)
                    .map_err(|err| format!("check event presence: {err}"))?
                {
                    response_items.push(SyncItem::NeedId(NeedIdEvent {
                        connection_id: event.connection_id,
                        id: event.id,
                    }));
                }
            }
            SyncItem::NeedId(event) => {
                observe_connection(&mut frame_connection_id, event.connection_id)?;
                requested_ids.push(event.id);
            }
            SyncItem::Data(mut event) => {
                observe_connection(&mut frame_connection_id, event.connection_id)?;
                received_event_bytes.append(&mut event.items);
            }
        }
    }

    let Some(connection_id) = frame_connection_id else {
        return Ok(SyncJobOutput {
            deleted_rows,
            ..SyncJobOutput::default()
        });
    };
    if connection_id != expected_connection_id {
        return Err("sync frame used a different connection id".to_string());
    }

    let mut frames = Vec::new();
    let sent_events = emit_control_and_requested_data(
        store,
        connection_id,
        response_items,
        &requested_ids,
        &mut frames,
    )?;
    let rows = frames
        .into_iter()
        .map(|frame| outbox::projector::queue(connection_id, event_id(&frame), frame))
        .collect();
    let received_events = received_event_bytes.len();

    Ok(SyncJobOutput {
        rows,
        deleted_rows,
        work: Vec::new(),
        received_event_bytes,
        sent_events,
        received_events,
    })
}

fn handle_compare(
    store: &Store,
    event: CompareEvent,
    response_items: &mut Vec<SyncItem>,
    requested_ids: &mut Vec<crate::store::EventId>,
    deleted_rows: &mut Vec<TableRowDeletion>,
) -> Result<(), String> {
    if !super::compare::projector::has_payload(&event.message) {
        return Ok(());
    }

    let storage = store.storage()?;
    if queries::initiator_session_exists(store, event.connection_id)? {
        let mut negentropy = Negentropy::borrowed(&storage, 0)
            .map_err(|err| format!("continue negentropy: {err:?}"))?;
        negentropy.set_initiator();
        let mut have_ids: Vec<Id> = Vec::new();
        let mut need_ids: Vec<Id> = Vec::new();
        if let Some(message) = negentropy
            .reconcile_with_ids(&event.message, &mut have_ids, &mut need_ids)
            .map_err(|err| format!("reconcile negentropy as initiator: {err:?}"))?
        {
            response_items.push(SyncItem::Compare(CompareEvent {
                connection_id: event.connection_id,
                message,
            }));
        } else {
            deleted_rows.push(queries::initiator_session_delete(event.connection_id));
        }
        for id in have_ids {
            requested_ids.push(id.to_bytes());
        }
        for id in need_ids {
            response_items.push(SyncItem::NeedId(NeedIdEvent {
                connection_id: event.connection_id,
                id: id.to_bytes(),
            }));
        }
        return Ok(());
    }

    let mut negentropy = Negentropy::borrowed(&storage, 0)
        .map_err(|err| format!("reconcile negentropy: {err:?}"))?;
    let message = negentropy
        .reconcile(&event.message)
        .map_err(|err| format!("reconcile negentropy as responder: {err:?}"))?;
    if message.len() > 1 {
        response_items.push(SyncItem::Compare(CompareEvent {
            connection_id: event.connection_id,
            message,
        }));
    }
    Ok(())
}

fn observe_connection(
    frame_connection_id: &mut Option<crate::store::EventId>,
    connection_id: crate::store::EventId,
) -> Result<(), String> {
    if let Some(existing) = frame_connection_id {
        if *existing != connection_id {
            return Err("sync frame mixed connection ids".to_string());
        }
    } else {
        *frame_connection_id = Some(connection_id);
    }
    Ok(())
}

fn emit_control_and_requested_data(
    context: &impl ReadContext,
    connection_id: crate::store::EventId,
    control_items: Vec<SyncItem>,
    requested_ids: &[crate::store::EventId],
    frames: &mut Vec<Vec<u8>>,
) -> Result<usize, String> {
    if requested_ids.is_empty() {
        emit_items(control_items, frames);
        return Ok(0);
    }

    let mut ids = requested_ids.to_vec();
    ids.sort();
    ids.dedup();

    let mut sent = 0;
    let mut pending_control = control_items;
    let mut data_items = Vec::new();
    let mut encoded_len = FRAME_HEADER_BYTES + DATA_ITEM_HEADER_BYTES;

    for id in ids {
        let Some(item) = context.event_byte(&id)? else {
            continue;
        };
        let entry_len = DATA_ENTRY_BYTES + item.len();
        if entry_len > FRAME_TARGET_BYTES {
            return Err(format!(
                "event is too large for a sync data frame: {} bytes",
                item.len()
            ));
        }
        if !data_items.is_empty() && encoded_len + entry_len > FRAME_TARGET_BYTES {
            sent += emit_data_frame(
                std::mem::take(&mut pending_control),
                connection_id,
                std::mem::take(&mut data_items),
                true,
                frames,
            );
            encoded_len = FRAME_HEADER_BYTES + DATA_ITEM_HEADER_BYTES;
        }
        encoded_len += entry_len;
        data_items.push(item);
    }

    if data_items.is_empty() {
        emit_items(pending_control, frames);
    } else {
        sent += emit_data_frame(pending_control, connection_id, data_items, false, frames);
    }
    Ok(sent)
}

fn emit_items(items: Vec<SyncItem>, frames: &mut Vec<Vec<u8>>) {
    if !items.is_empty() {
        frames.push(frame_codec::encode(&Frame { more: false, items }));
    }
}

fn emit_data_frame(
    control_items: Vec<SyncItem>,
    connection_id: crate::store::EventId,
    data_items: Vec<Vec<u8>>,
    more: bool,
    frames: &mut Vec<Vec<u8>>,
) -> usize {
    let sent = data_items.len();
    let mut items = control_items;
    items.push(SyncItem::Data(DataEvent {
        connection_id,
        items: data_items,
    }));
    frames.push(frame_codec::encode(&Frame { more, items }));
    sent
}
