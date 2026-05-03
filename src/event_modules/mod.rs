pub mod connection;
pub mod content;
pub mod identity;
pub mod sync;
pub mod test_events;

use std::net::SocketAddr;

use crate::store::{
    CommandOutput, EventRecord, ModuleJobOutput, ProjectionOutput, Store, TableRow,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct Modules;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameMetadata {
    pub origin: SocketAddr,
    pub remember_origin: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleFrameReport {
    pub events: Vec<EventRecord>,
    pub rows: Vec<TableRow>,
    pub outgoing: Vec<Vec<u8>>,
    pub queued_route: Option<connection::connection_record::types::ConnectionId>,
    pub established_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
    pub received_event_bytes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSync {
    pub target: SocketAddr,
    pub outgoing: Vec<Vec<u8>>,
    pub sent_outbox: Vec<Vec<u8>>,
    pub sent_events: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainedOutbox {
    pub outgoing: Vec<Vec<u8>>,
    pub sent_outbox: Vec<Vec<u8>>,
}

impl Modules {
    pub fn new() -> Self {
        Self
    }

    pub fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        record_from_bytes(bytes)
    }

    pub fn create_invite(
        &self,
        store: &Store,
        public_addr: SocketAddr,
    ) -> Result<CommandOutput<String>, String> {
        let local = self.local_keypair(store)?;
        let invite = identity::invite::commands::create(local.value, public_addr);
        Ok(merge_outputs(local.events, invite))
    }

    pub fn invite_addr(&self, invite: &str) -> Result<SocketAddr, String> {
        identity::invite::commands::addr(invite)
    }

    pub fn generate_content(
        &self,
        store: &Store,
        num_events: usize,
        event_size: usize,
    ) -> Result<CommandOutput<content::content_event::commands::GenerateReport>, String> {
        let start = store
            .max_timestamp()
            .map_err(|err| format!("load max timestamp: {err}"))?
            .saturating_add(1);
        content::content_event::commands::generate(start, num_events, event_size)
    }

    pub fn stage_dependent_events(
        &self,
        store: &Store,
        events: usize,
        deps_per_event: usize,
    ) -> Result<CommandOutput<test_events::dependent_event::commands::StageReport>, String> {
        let start = store
            .max_timestamp()
            .map_err(|err| format!("load max timestamp: {err}"))?
            .saturating_add(1);
        test_events::dependent_event::commands::stage(events, deps_per_event, start)
    }

    pub fn staged_dependent_records(&self, store: &Store) -> Result<Vec<EventRecord>, String> {
        test_events::dependent_event::queries::staged_records(store)
    }

    pub fn create_connection_request(
        &self,
        store: &Store,
        invite: &str,
    ) -> Result<CommandOutput<connection::connection_request::commands::OutboundRequest>, String>
    {
        let local = self.local_keypair(store)?;
        let request = connection::connection_request::commands::create(local.value, invite)?;
        Ok(merge_outputs(local.events, request))
    }

    pub fn ingest_frame(
        &self,
        store: &Store,
        origin: SocketAddr,
        remember_origin: bool,
        bytes: Vec<u8>,
    ) -> Result<ModuleFrameReport, String> {
        let metadata = FrameMetadata {
            origin,
            remember_origin,
        };
        let local = self.existing_local_keypair(store)?;
        let transit = connection::transit::projector::unwrap(local, &bytes, |connection_id| {
            connection::connection_record::queries::remote_endpoint(store, connection_id)
        })?;
        if connection::connection_record::types::is_connection_event(&transit.inner) {
            return self.ingest_connection_frame(store, metadata, transit.inner);
        }
        let connection_id = transit
            .connection_id
            .ok_or_else(|| "sync frame requires connection transit".to_string())?;
        self.ingest_sync_frame(store, connection_id, &transit.inner)
    }

    fn ingest_connection_frame(
        &self,
        store: &Store,
        metadata: FrameMetadata,
        bytes: Vec<u8>,
    ) -> Result<ModuleFrameReport, String> {
        let mut result = ModuleFrameReport::default();
        if connection::connection_request::codec::is_request(&bytes) {
            result
                .events
                .push(connection::connection_request::codec::record_from_bytes(
                    bytes.clone(),
                )?);
            let event = connection::connection_request::codec::decode(&bytes)?;
            let authorized = identity::invite::queries::bootstrap_hash_is_authorized(
                store,
                &event.bootstrap_hash,
            )?;
            let local = self.local_keypair(store)?;
            let connection =
                connection::connection_request::commands::accept(local.value, authorized, bytes)?;
            let connection = merge_outputs(local.events, connection);
            self.apply_connection_result(metadata, connection, &mut result);
        } else if connection::connection_ack::codec::is_ack(&bytes) {
            result
                .events
                .push(connection::connection_ack::codec::record_from_bytes(
                    bytes.clone(),
                )?);
            let event = connection::connection_ack::codec::decode(&bytes)?;
            let request_bytes =
                connection::connection_record::queries::event_bytes(store, &event.request_id)?
                    .ok_or_else(|| "connection ack references unknown request".to_string())?;
            let local = self.local_keypair(store)?;
            let connection =
                connection::connection_ack::commands::accept(local.value, request_bytes, bytes)?;
            let connection = merge_outputs(local.events, connection);
            self.apply_connection_result(metadata, connection, &mut result);
        } else {
            return Err("unknown connection event".to_string());
        }
        Ok(result)
    }

    fn apply_connection_result(
        &self,
        metadata: FrameMetadata,
        connection: CommandOutput<connection::connection_record::types::InboundConnection>,
        result: &mut ModuleFrameReport,
    ) {
        result.events.extend(connection.events);
        result.outgoing.extend(connection.value.outgoing);
        if let Some(connection_id) = connection.value.connection_id {
            if metadata.remember_origin {
                result
                    .events
                    .push(connection::transport_target::commands::record(
                        connection_id,
                        metadata.origin,
                    ));
            }
            result.established_routes += 1;
        }
    }

    pub fn start_sync(&self, store: &Store) -> Result<ProjectionOutput, String> {
        let routes = connection::transport_target::queries::routes(store)?;
        if routes.is_empty() {
            return Ok(ProjectionOutput::default());
        }
        let required_index_seq = store
            .max_applied_shared_seq()
            .map_err(|err| format!("load sync frontier: {err}"))?;
        Ok(ProjectionOutput::rows(
            routes
                .into_iter()
                .map(|route| sync::jobs::queue_start(route.connection_id, required_index_seq))
                .collect(),
        ))
    }

    pub fn drain_outbox_routes(&self, store: &Store) -> Result<Vec<OutboundSync>, String> {
        let routes = connection::transport_target::queries::routes(store)?;
        let mut outbound = Vec::new();
        for route in routes {
            let drained = self.drain_outbox_for_route(store, route.connection_id)?;
            if drained.outgoing.is_empty() {
                continue;
            }
            outbound.push(OutboundSync {
                target: route.addr,
                outgoing: drained.outgoing,
                sent_outbox: drained.sent_outbox,
                sent_events: 0,
            });
        }
        Ok(outbound)
    }

    pub fn drain_outbox_for_route(
        &self,
        store: &Store,
        connection_id: connection::connection_record::types::ConnectionId,
    ) -> Result<DrainedOutbox, String> {
        let items = connection::outbox::queries::items_for_connection(store, connection_id)?;
        if items.is_empty() {
            return Ok(DrainedOutbox::default());
        }
        let local = self.existing_local_keypair(store)?;
        let remote =
            connection::connection_record::queries::remote_endpoint(store, &connection_id)?;
        let mut outgoing = Vec::with_capacity(items.len());
        let mut sent_outbox = Vec::with_capacity(items.len());
        for item in items {
            outgoing.push(connection::transit::commands::create_connection(
                &local,
                remote,
                connection_id,
                item.event_bytes,
            )?);
            sent_outbox.push(item.key.to_bytes());
        }
        Ok(DrainedOutbox {
            outgoing,
            sent_outbox,
        })
    }

    pub fn mark_outbox_sent(&self, store: &Store, sent_outbox: Vec<Vec<u8>>) -> Result<(), String> {
        if sent_outbox.is_empty() {
            return Ok(());
        }
        connection::outbox::queries::delete_encoded(store, sent_outbox)
    }

    pub fn connection_count(&self, store: &Store) -> Result<usize, String> {
        connection::connection_record::queries::connection_count(store)
    }

    pub fn connection_event_count(&self, store: &Store) -> Result<usize, String> {
        connection::connection_record::queries::connection_event_count(store)
    }

    fn ingest_sync_frame(
        &self,
        store: &Store,
        connection_id: connection::connection_record::types::ConnectionId,
        bytes: &[u8],
    ) -> Result<ModuleFrameReport, String> {
        let mut result = ModuleFrameReport::default();
        let frame_connection_id = sync::frame::codec::connection_id(bytes)?;
        if frame_connection_id != connection_id {
            return Err("sync frame used a different connection id".to_string());
        }
        let required_index_seq = store
            .max_applied_shared_seq()
            .map_err(|err| format!("load sync frontier: {err}"))?;
        result.rows.push(sync::jobs::queue_inbound_frame(
            connection_id,
            required_index_seq,
            bytes.to_vec(),
        ));
        result.queued_route = Some(connection_id);
        Ok(result)
    }

    pub fn next_job(&self, store: &Store) -> Result<Option<ModuleJobOutput>, String> {
        let Some(output) = sync::jobs::next(store)? else {
            return Ok(None);
        };
        let mut events = output.events;
        for bytes in output.received_event_bytes {
            events.push(record_from_bytes(bytes)?);
        }
        Ok(Some(ModuleJobOutput {
            rows: output.rows,
            deleted_rows: output.deleted_rows,
            events,
            sent_events: output.sent_events,
            received_events: output.received_events,
        }))
    }

    fn local_keypair(
        &self,
        store: &Store,
    ) -> Result<CommandOutput<identity::endpoint::types::EndpointKeypair>, String> {
        match identity::endpoint::queries::local_keypair(store)? {
            Some(local) => Ok(CommandOutput::new(local)),
            None => Ok(identity::endpoint::commands::create_local_keypair()),
        }
    }

    pub fn project_record(
        &self,
        store: &Store,
        record: &EventRecord,
    ) -> Result<ProjectionOutput, String> {
        let bytes = &record.canonical_bytes;
        if let Some(output) = identity::project_record(bytes)? {
            return Ok(output);
        }
        if connection::is_projection_record(bytes) {
            let local = self.existing_local_keypair(store)?;
            return connection::project_record(store, bytes, local.endpoint);
        }
        if let Some(output) = sync::project_record(bytes)? {
            return Ok(output);
        }
        if let Some(output) = content::project_record(bytes)? {
            return Ok(output);
        }
        if let Some(output) = test_events::project_record(bytes)? {
            return Ok(output);
        }
        let tag = bytes.first().copied().unwrap_or_default();
        Err(format!("unknown event type {tag}"))
    }

    fn existing_local_keypair(
        &self,
        store: &Store,
    ) -> Result<identity::endpoint::types::EndpointKeypair, String> {
        identity::endpoint::queries::local_keypair(store)?
            .ok_or_else(|| "local endpoint is missing".to_string())
    }
}

fn merge_outputs<T>(
    mut events: Vec<EventRecord>,
    mut output: CommandOutput<T>,
) -> CommandOutput<T> {
    events.append(&mut output.events);
    output.events = events;
    output
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    if connection::connection_request::codec::is_request(&bytes) {
        return connection::connection_request::codec::record_from_bytes(bytes);
    }
    if connection::connection_ack::codec::is_ack(&bytes) {
        return connection::connection_ack::codec::record_from_bytes(bytes);
    }
    if sync::frame::codec::is_frame(&bytes) {
        return sync::frame::codec::record_from_bytes(bytes);
    }
    let tag = bytes
        .first()
        .ok_or_else(|| "empty event bytes".to_string())?;
    match *tag {
        identity::endpoint::codec::TYPE_LOCAL_ENDPOINT => {
            identity::endpoint::codec::record_from_bytes(bytes)
        }
        identity::invite::codec::TYPE_INVITE_SECRET => {
            identity::invite::codec::record_from_bytes(bytes)
        }
        connection::transport_target::codec::TYPE_TRANSPORT_TARGET => {
            connection::transport_target::codec::record_from_bytes(bytes)
        }
        content::content_event::codec::TYPE_CONTENT => {
            content::content_event::codec::record_from_bytes(bytes)
        }
        test_events::dependent_event::codec::TYPE_DEPENDENT_EVENT => {
            test_events::dependent_event::codec::record_from_bytes(bytes)
        }
        test_events::dependent_event::codec::TYPE_STAGED_DEPENDENT_EVENT => {
            test_events::dependent_event::codec::staged_record_from_bytes(bytes)
        }
        other => Err(format!("unknown event type {other}")),
    }
}
