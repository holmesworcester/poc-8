use crate::store::{EventId, Store};

use super::codec::{self, Frame, SyncItem};
use super::{projector, queries};

const FRAME_TARGET_BYTES: usize = 32 * 1024 * 1024;
const FRAME_HEADER_BYTES: usize = 14;
const DATA_ITEM_HEADER_BYTES: usize = 1 + 32 + 4;
const DATA_ENTRY_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub sent_events: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Incoming {
    pub connection_id: Option<EventId>,
    pub compare: Option<[codec::BucketSummary; codec::BUCKETS]>,
    pub haves: Vec<(u8, EventId)>,
    pub needs: Vec<EventId>,
    pub received_events: usize,
}

pub fn emit_start(
    store: &Store,
    connection_id: EventId,
    mut emit: impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<SyncReport, String> {
    let mut items = vec![SyncItem::Compare {
        connection_id,
        summary: queries::summary(store)?,
    }];
    items.extend(all_have_items(store, connection_id)?);
    emit_items(items, &mut emit)?;
    Ok(SyncReport::default())
}

pub fn absorb_frame(store: &Store, bytes: &[u8], incoming: &mut Incoming) -> Result<bool, String> {
    let frame = codec::decode(bytes)?;
    for item in frame.items {
        match item {
            SyncItem::Compare {
                connection_id,
                summary,
            } => {
                observe_connection(incoming, connection_id)?;
                incoming.compare = Some(summary);
            }
            SyncItem::HaveId {
                connection_id,
                bucket,
                id,
            } => {
                observe_connection(incoming, connection_id)?;
                incoming.haves.push((bucket, id));
            }
            SyncItem::NeedId { connection_id, id } => {
                observe_connection(incoming, connection_id)?;
                incoming.needs.push(id);
            }
            SyncItem::Data {
                connection_id,
                items,
            } => {
                observe_connection(incoming, connection_id)?;
                incoming.received_events += queries::insert_events(store, items)?;
            }
        }
    }
    Ok(frame.more)
}

pub fn emit_start_response(
    store: &Store,
    incoming: Incoming,
    mut emit: impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<SyncReport, String> {
    let connection_id = incoming_connection_id(&incoming)?;
    let mut items = Vec::new();
    let local = queries::summary(store)?;
    items.push(SyncItem::Compare {
        connection_id,
        summary: local,
    });
    if let Some(remote) = incoming.compare {
        items.extend(have_items_for_compare(store, connection_id, local, remote)?);
    }
    add_needs_for_haves(store, &incoming, &mut items)?;
    emit_items(items, &mut emit)?;
    Ok(SyncReport {
        sent_events: 0,
        received_events: incoming.received_events,
    })
}

pub fn emit_answer_response(
    store: &Store,
    incoming: Incoming,
    mut emit: impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<SyncReport, String> {
    let connection_id = incoming_connection_id(&incoming)?;
    let mut control_items = Vec::new();
    add_needs_for_haves(store, &incoming, &mut control_items)?;
    let sent_events = emit_control_and_requested_data(
        store,
        connection_id,
        control_items,
        &incoming.needs,
        &mut emit,
    )?;
    Ok(SyncReport {
        sent_events,
        received_events: incoming.received_events,
    })
}

pub fn emit_finish_response(
    store: &Store,
    incoming: Incoming,
    mut emit: impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<SyncReport, String> {
    let connection_id = incoming_connection_id(&incoming)?;
    let sent_events = emit_control_and_requested_data(
        store,
        connection_id,
        Vec::new(),
        &incoming.needs,
        &mut emit,
    )?;
    Ok(SyncReport {
        sent_events,
        received_events: incoming.received_events,
    })
}

pub fn finish(incoming: Incoming) -> SyncReport {
    SyncReport {
        sent_events: 0,
        received_events: incoming.received_events,
    }
}

fn observe_connection(incoming: &mut Incoming, connection_id: EventId) -> Result<(), String> {
    if let Some(existing) = incoming.connection_id {
        if existing != connection_id {
            return Err("sync frame mixed connection ids".to_string());
        }
    } else {
        incoming.connection_id = Some(connection_id);
    }
    Ok(())
}

fn incoming_connection_id(incoming: &Incoming) -> Result<EventId, String> {
    incoming
        .connection_id
        .ok_or_else(|| "sync frame had no connection id".to_string())
}

fn all_have_items(store: &Store, connection_id: EventId) -> Result<Vec<SyncItem>, String> {
    let mut items = Vec::new();
    for bucket in 0..codec::BUCKETS {
        let ids = queries::ids_in_bucket(store, bucket as u8)?;
        for id in ids {
            items.push(SyncItem::HaveId {
                connection_id,
                bucket: bucket as u8,
                id,
            });
        }
    }
    Ok(items)
}

fn have_items_for_compare(
    store: &Store,
    connection_id: EventId,
    local: [codec::BucketSummary; codec::BUCKETS],
    remote: [codec::BucketSummary; codec::BUCKETS],
) -> Result<Vec<SyncItem>, String> {
    let mut items = Vec::new();
    for bucket in projector::differing_buckets(&local, &remote) {
        let ids = queries::ids_in_bucket(store, bucket)?;
        for id in ids {
            items.push(SyncItem::HaveId {
                connection_id,
                bucket,
                id,
            });
        }
    }
    Ok(items)
}

fn add_needs_for_haves(
    store: &Store,
    incoming: &Incoming,
    out: &mut Vec<SyncItem>,
) -> Result<(), String> {
    let connection_id = incoming_connection_id(incoming)?;
    let mut ids = Vec::new();
    ids.extend(incoming.haves.iter().map(|(_, id)| *id));
    ids.sort();
    ids.dedup();
    for id in missing_ids(store, &ids)? {
        out.push(SyncItem::NeedId { connection_id, id });
    }
    Ok(())
}

fn missing_ids(store: &Store, ids: &[EventId]) -> Result<Vec<EventId>, String> {
    let mut present = Vec::new();
    for id in ids {
        if queries::has_event(store, id)? {
            present.push(*id);
        }
    }
    Ok(projector::missing_ids(
        |id| present.binary_search(id).is_ok(),
        ids,
    ))
}

fn emit_control_and_requested_data(
    store: &Store,
    connection_id: EventId,
    control_items: Vec<SyncItem>,
    requested_ids: &[EventId],
    emit: &mut impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<usize, String> {
    if requested_ids.is_empty() {
        emit_items(control_items, emit)?;
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
        let Some(item) = queries::event_byte(store, &id)? else {
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
            sent += emit_frame(
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
        emit_items(pending_control, emit)?;
    } else {
        sent += emit_frame(pending_control, connection_id, data_items, false, emit)?;
    }
    Ok(sent)
}

fn emit_items(
    items: Vec<SyncItem>,
    emit: &mut impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<(), String> {
    if items.is_empty() {
        return Ok(());
    }
    emit(codec::encode(&Frame { more: false, items }))
}

fn emit_frame(
    control_items: Vec<SyncItem>,
    connection_id: EventId,
    data_items: Vec<Vec<u8>>,
    more: bool,
    emit: &mut impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<usize, String> {
    let sent = data_items.len();
    let mut items = control_items;
    items.push(SyncItem::Data {
        connection_id,
        items: data_items,
    });
    emit(codec::encode(&Frame { more, items }))?;
    Ok(sent)
}
