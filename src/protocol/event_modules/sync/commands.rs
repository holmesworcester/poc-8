//! Sync domain commands.
//!
//! Commands decide which sync events or durable event ids should be produced
//! from explicit protocol context. They do not claim queues, read storage,
//! write queue rows, consume work, or touch TCP.

use crate::protocol::event_modules::connection;
use crate::protocol::event_modules::sync::compare;
use crate::protocol::event_modules::sync::compare::types::TimestampRange;
use crate::protocol::event_modules::types::{EventId, EventRecord};
use crate::protocol::event_modules::worker::CommandOutput;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SyncSelection {
    #[default]
    All,
    Today,
}

/// Summary of a sync start command.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncStartReport {
    pub sent_events: usize,
}

/// Records and durable send ids produced by handling inbound sync work.
///
/// `events` are connection-scoped sync records that should be admitted so their
/// projector can queue them for transit. `transit_out` names the durable shared
/// event ids requested by the peer and the route they should use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncWorkReport {
    pub events: Vec<EventRecord>,
    pub processed_work: usize,
    pub sent_events: usize,
    pub transit_out: Vec<SyncTransitOut>,
    pub send_event_ids: Vec<EventId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncTransitOut {
    pub connection_id: connection::types::ConnectionId,
    pub event_id: EventId,
}

pub(crate) fn start_for_connection(
    context: &impl compare::commands::ReadContext,
    connection_id: connection::types::ConnectionId,
    range: TimestampRange,
) -> Result<CommandOutput<SyncStartReport>, String> {
    let report = compare::commands::start(context, connection_id, range)?;
    Ok(CommandOutput::with_events(
        SyncStartReport {
            sent_events: report.sent_events,
        },
        report.events,
    ))
}

pub(crate) fn handle_inbound_event(
    context: &impl compare::commands::ReadContext,
    expected_connection_id: connection::types::ConnectionId,
    response_connection_id: connection::types::ConnectionId,
    event_bytes: &[u8],
) -> Result<SyncWorkReport, String> {
    let report = compare::commands::handle_inbound_event(
        context,
        expected_connection_id,
        response_connection_id,
        event_bytes,
    )?;
    let mut out = SyncWorkReport {
        events: report.events,
        processed_work: 1,
        sent_events: report.sent_events,
        ..SyncWorkReport::default()
    };
    for event_id in report.send_event_ids {
        out.transit_out.push(SyncTransitOut {
            connection_id: response_connection_id,
            event_id,
        });
        out.send_event_ids.push(event_id);
    }
    Ok(out)
}
