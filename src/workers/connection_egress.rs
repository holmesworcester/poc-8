//! Connection egress worker.
//!
//! Input queue: `connection.outbox`.
//! Owned state: connection route/scope policy and transit wrapping.
//! Output queue: `core.network.outbound`.
//! Ack: connection outbox rows are deleted only after core reports the
//! corresponding outbound network rows were sent.

use crate::core::store::Store;
use crate::protocol::event_modules::connection::types::RouteExchangeReport;
use crate::workers::connection::{self, ConnectionRegistry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    ExchangeRoutes { fail_on_route_error: bool },
}

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<RouteExchangeReport, String>
where
    R: ConnectionRegistry,
{
    match work {
        Work::ExchangeRoutes {
            fail_on_route_error,
        } => connection::exchange_outbound_routes(store, registry, fail_on_route_error),
    }
}
