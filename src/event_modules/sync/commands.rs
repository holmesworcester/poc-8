use std::net::{SocketAddr, TcpListener, TcpStream};

use crate::network;
use crate::store::{EventId, Store};

use super::codec::{self, Message};
use super::{projector, queries};

const EVENT_FRAME_LIMIT_BYTES: usize = 32 * 1024 * 1024;
const EVENTS_MESSAGE_OVERHEAD_BYTES: usize = 5;
const EVENT_ENTRY_OVERHEAD_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub peers_synced: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServeReport {
    pub accepted_connections: usize,
    pub received_events: usize,
}

pub fn connect(store: &Store, addr: SocketAddr) -> Result<(), String> {
    let mut stream = network::connect(addr).map_err(|err| format!("open tcp stream: {err}"))?;
    write_message(&mut stream, &Message::Hello)?;
    match read_message(&mut stream)? {
        Message::HelloAck => {
            store
                .insert_peer(addr)
                .map_err(|err| format!("store peer: {err}"))?;
            Ok(())
        }
        other => Err(format!("expected hello ack, got {other:?}")),
    }
}

pub fn sync(store: &Store) -> Result<SyncReport, String> {
    let peers = store.peers().map_err(|err| format!("load peers: {err}"))?;
    let mut report = SyncReport::default();
    for peer in peers {
        let peer_report = sync_peer(store, peer)?;
        report.peers_synced += 1;
        report.sent_events += peer_report.sent_events;
        report.received_events += peer_report.received_events;
    }
    Ok(report)
}

pub fn serve(
    store: &Store,
    listener: TcpListener,
    accept_count: usize,
) -> Result<ServeReport, String> {
    let mut report = ServeReport::default();
    for _ in 0..accept_count {
        let (mut stream, _) = listener
            .accept()
            .map_err(|err| format!("accept tcp stream: {err}"))?;
        let received = serve_stream(store, &mut stream)?;
        report.accepted_connections += 1;
        report.received_events += received;
    }
    Ok(report)
}

fn sync_peer(store: &Store, addr: SocketAddr) -> Result<SyncReport, String> {
    let mut stream = network::connect(addr).map_err(|err| format!("open tcp stream: {err}"))?;
    let local = queries::summary(store)?;
    write_message(&mut stream, &Message::Summary(local))?;

    let remote = expect_summary(read_message(&mut stream)?)?;
    let differing = projector::differing_buckets(&local, &remote);
    for bucket in &differing {
        write_message(
            &mut stream,
            &Message::Have {
                bucket: *bucket,
                ids: queries::ids_in_bucket(store, *bucket)?,
            },
        )?;
    }
    write_message(&mut stream, &Message::Done)?;

    let mut sent_events = 0;
    let mut ids_to_request = Vec::new();
    loop {
        match read_message(&mut stream)? {
            Message::Have { ids, .. } => {
                ids_to_request.extend(missing_ids(store, &ids)?);
            }
            Message::Need { ids } => {
                sent_events += send_events(store, &mut stream, &ids)?;
            }
            Message::Done => break,
            other => return Err(format!("unexpected sync phase message {other:?}")),
        }
    }

    write_message(
        &mut stream,
        &Message::Need {
            ids: ids_to_request,
        },
    )?;
    write_message(&mut stream, &Message::Done)?;

    let mut received_events = 0;
    loop {
        match read_message(&mut stream)? {
            Message::Events { events } => {
                received_events += queries::insert_events(store, events)?;
            }
            Message::Done => break,
            other => return Err(format!("unexpected final sync message {other:?}")),
        }
    }

    Ok(SyncReport {
        peers_synced: 1,
        sent_events,
        received_events,
    })
}

fn serve_stream(store: &Store, stream: &mut TcpStream) -> Result<usize, String> {
    match read_message(stream)? {
        Message::Hello => {
            write_message(stream, &Message::HelloAck)?;
            Ok(0)
        }
        Message::Summary(remote) => serve_sync(store, stream, remote),
        other => Err(format!("unexpected first message {other:?}")),
    }
}

fn serve_sync(
    store: &Store,
    stream: &mut TcpStream,
    remote: [super::codec::BucketSummary; super::codec::BUCKETS],
) -> Result<usize, String> {
    let local = queries::summary(store)?;
    write_message(stream, &Message::Summary(local))?;
    let differing = projector::differing_buckets(&local, &remote);

    let mut ids_to_request = Vec::new();
    loop {
        match read_message(stream)? {
            Message::Have { bucket, ids } => {
                ids_to_request.extend(missing_ids(store, &ids)?);
                if differing.contains(&bucket) {
                    write_message(
                        stream,
                        &Message::Have {
                            bucket,
                            ids: queries::ids_in_bucket(store, bucket)?,
                        },
                    )?;
                }
            }
            Message::Done => break,
            other => return Err(format!("unexpected have phase message {other:?}")),
        }
    }

    write_message(
        stream,
        &Message::Need {
            ids: ids_to_request,
        },
    )?;
    write_message(stream, &Message::Done)?;

    let mut received_events = 0;
    let mut ids_to_send = Vec::new();
    loop {
        match read_message(stream)? {
            Message::Events { events } => {
                received_events += queries::insert_events(store, events)?;
            }
            Message::Need { ids } => ids_to_send.extend(ids),
            Message::Done => break,
            other => return Err(format!("unexpected event phase message {other:?}")),
        }
    }

    send_events(store, stream, &ids_to_send)?;
    write_message(stream, &Message::Done)?;
    Ok(received_events)
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

fn send_events(store: &Store, stream: &mut TcpStream, ids: &[EventId]) -> Result<usize, String> {
    let mut sent = 0;
    let mut events = Vec::new();
    let mut encoded_len = EVENTS_MESSAGE_OVERHEAD_BYTES;

    for id in ids {
        let Some(event) = queries::event_byte(store, id)? else {
            continue;
        };
        let entry_len = EVENT_ENTRY_OVERHEAD_BYTES + event.len();
        if entry_len > EVENT_FRAME_LIMIT_BYTES {
            return Err(format!(
                "event is too large for a sync event frame: {} bytes",
                event.len()
            ));
        }
        if !events.is_empty() && encoded_len + entry_len > EVENT_FRAME_LIMIT_BYTES {
            sent += flush_events(stream, &mut events)?;
            encoded_len = EVENTS_MESSAGE_OVERHEAD_BYTES;
        }
        encoded_len += entry_len;
        events.push(event);
    }

    sent += flush_events(stream, &mut events)?;
    Ok(sent)
}

fn flush_events(stream: &mut TcpStream, events: &mut Vec<Vec<u8>>) -> Result<usize, String> {
    if events.is_empty() {
        return Ok(0);
    }
    let sent = events.len();
    write_message(
        stream,
        &Message::Events {
            events: std::mem::take(events),
        },
    )?;
    Ok(sent)
}

fn expect_summary(
    message: Message,
) -> Result<[super::codec::BucketSummary; super::codec::BUCKETS], String> {
    match message {
        Message::Summary(summary) => Ok(summary),
        other => Err(format!("expected summary, got {other:?}")),
    }
}

fn write_message(stream: &mut TcpStream, message: &Message) -> Result<(), String> {
    network::write_frame(stream, &codec::encode(message))
        .map_err(|err| format!("write frame: {err}"))
}

fn read_message(stream: &mut TcpStream) -> Result<Message, String> {
    let bytes = network::read_frame(stream).map_err(|err| format!("read frame: {err}"))?;
    codec::decode(&bytes)
}
