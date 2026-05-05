//! Connection ingress worker.
//!
//! Input queue: `core.network.inbound` rows handed over by the TCP pump.
//! Owned state: connection receive policy and route-learning admission context.
//! Output queues: event ingress plus same-route outbound network rows.
//! Ack: core TCP deletes the inbound row after this worker returns successfully.

use crate::core::network_queues::InboundNetworkRow;
use crate::core::store::Store;
use crate::workers::connection::{self, ConnectionRegistry, NetworkIngestResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    HandleInbound {
        inbound: InboundNetworkRow,
        remember_origin: bool,
    },
}

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<NetworkIngestResult, String>
where
    R: ConnectionRegistry,
{
    match work {
        Work::HandleInbound {
            inbound,
            remember_origin,
        } => connection::ingest_network(store, registry, inbound, remember_origin),
    }
}
