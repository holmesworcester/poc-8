use negentropy::{Id, Negentropy};

use crate::store::EventId;

use super::super::data::types::DataEvent;
use super::super::frame::codec as frame_codec;
use super::super::frame::types::{Frame, SyncItem};
use super::super::need_id::types::NeedIdEvent;
use super::queries::ReadContext;
use super::types::CompareEvent;

const FRAME_TARGET_BYTES: usize = 32 * 1024 * 1024;
const FRAME_HEADER_BYTES: usize = 14;
const DATA_ITEM_HEADER_BYTES: usize = 1 + 32 + 4;
const DATA_ENTRY_BYTES: usize = 4;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub sent_events: usize,
    pub received_events: usize,
    pub received_event_bytes: Vec<Vec<u8>>,
}

pub fn start(
    context: &impl ReadContext,
    connection_id: EventId,
    mut emit: impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<SyncReport, String> {
    let storage = context.storage()?;
    let mut negentropy =
        Negentropy::borrowed(&storage, 0).map_err(|err| format!("start negentropy: {err:?}"))?;
    let message = negentropy
        .initiate()
        .map_err(|err| format!("initiate negentropy: {err:?}"))?;
    emit_frame(
        vec![SyncItem::Compare(CompareEvent {
            connection_id,
            sender_is_initiator: true,
            message,
        })],
        &mut emit,
    )?;
    Ok(SyncReport::default())
}

pub fn ingest_frame(
    context: &impl ReadContext,
    expected_connection_id: EventId,
    bytes: &[u8],
    mut emit: impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<SyncReport, String> {
    let frame = frame_codec::decode(bytes)?;
    let mut frame_connection_id = None;
    let mut response_items = Vec::new();
    let mut requested_ids = Vec::new();
    let mut received_event_bytes = Vec::new();

    for item in frame.items {
        match item {
            SyncItem::Compare(event) => {
                observe_connection(&mut frame_connection_id, event.connection_id)?;
                handle_compare(context, event, &mut response_items, &mut requested_ids)?;
            }
            SyncItem::HaveId(event) => {
                observe_connection(&mut frame_connection_id, event.connection_id)?;
                if !context.has_event(&event.id)? {
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
        return Ok(SyncReport::default());
    };
    if connection_id != expected_connection_id {
        return Err("sync frame used a different connection id".to_string());
    }

    let sent_events = emit_control_and_requested_data(
        context,
        connection_id,
        response_items,
        &requested_ids,
        &mut emit,
    )?;
    let received_events = received_event_bytes.len();

    Ok(SyncReport {
        sent_events,
        received_events,
        received_event_bytes,
    })
}

fn handle_compare(
    context: &impl ReadContext,
    event: CompareEvent,
    response_items: &mut Vec<SyncItem>,
    requested_ids: &mut Vec<EventId>,
) -> Result<(), String> {
    if !super::projector::has_payload(&event.message) {
        return Ok(());
    }

    let storage = context.storage()?;
    if event.sender_is_initiator {
        let mut negentropy = Negentropy::borrowed(&storage, 0)
            .map_err(|err| format!("reconcile negentropy as responder: {err:?}"))?;
        let message = negentropy
            .reconcile(&event.message)
            .map_err(|err| format!("reconcile negentropy as responder: {err:?}"))?;
        if message.len() > 1 {
            response_items.push(SyncItem::Compare(CompareEvent {
                connection_id: event.connection_id,
                sender_is_initiator: false,
                message,
            }));
        }
        return Ok(());
    }

    let mut negentropy = Negentropy::borrowed(&storage, 0)
        .map_err(|err| format!("reconcile negentropy as initiator: {err:?}"))?;
    negentropy.set_initiator();
    let mut have_ids: Vec<Id> = Vec::new();
    let mut need_ids: Vec<Id> = Vec::new();
    if let Some(message) = negentropy
        .reconcile_with_ids(&event.message, &mut have_ids, &mut need_ids)
        .map_err(|err| format!("reconcile negentropy as initiator: {err:?}"))?
    {
        response_items.push(SyncItem::Compare(CompareEvent {
            connection_id: event.connection_id,
            sender_is_initiator: true,
            message,
        }));
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
    Ok(())
}

fn observe_connection(
    frame_connection_id: &mut Option<EventId>,
    connection_id: EventId,
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
    connection_id: EventId,
    control_items: Vec<SyncItem>,
    requested_ids: &[EventId],
    emit: &mut impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<usize, String> {
    if requested_ids.is_empty() {
        emit_frame(control_items, emit)?;
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
                emit,
            )?;
            encoded_len = FRAME_HEADER_BYTES + DATA_ITEM_HEADER_BYTES;
        }
        encoded_len += entry_len;
        data_items.push(item);
    }

    if data_items.is_empty() {
        emit_frame(pending_control, emit)?;
    } else {
        sent += emit_data_frame(pending_control, connection_id, data_items, false, emit)?;
    }
    Ok(sent)
}

fn emit_frame(
    items: Vec<SyncItem>,
    emit: &mut impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<(), String> {
    if !items.is_empty() {
        emit(frame_codec::encode(&Frame { more: false, items }))?;
    }
    Ok(())
}

fn emit_data_frame(
    control_items: Vec<SyncItem>,
    connection_id: EventId,
    data_items: Vec<Vec<u8>>,
    more: bool,
    emit: &mut impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<usize, String> {
    let sent = data_items.len();
    let mut items = control_items;
    items.push(SyncItem::Data(DataEvent {
        connection_id,
        items: data_items,
    }));
    emit(frame_codec::encode(&Frame { more, items }))?;
    Ok(sent)
}
