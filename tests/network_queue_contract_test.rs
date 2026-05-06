use std::net::SocketAddr;

use topo::core::network_queues::{
    self, InboundNetworkRow, NetworkSource, NetworkTarget, OutboundNetworkRow,
};
use topo::core::store::Store;

#[test]
fn network_queues_are_opaque_and_idempotent_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open_disk_with_schemas(
        tmp.path().join("network-queues.db"),
        network_queues::SCHEMAS,
    )
    .unwrap();
    let addr: SocketAddr = "127.0.0.1:41000".parse().unwrap();
    let other_addr: SocketAddr = "127.0.0.1:41001".parse().unwrap();
    let target = NetworkTarget::new(addr);
    let other_target = NetworkTarget::new(other_addr);
    let source = NetworkSource::new(addr);

    let outbound = OutboundNetworkRow::new(target, b"opaque bytes".to_vec());
    let duplicate_outbound = OutboundNetworkRow::new(target, b"opaque bytes".to_vec());
    let other_outbound = OutboundNetworkRow::new(other_target, b"other target bytes".to_vec());
    assert_eq!(outbound.key, duplicate_outbound.key);
    assert_ne!(outbound.key, other_outbound.key);

    assert_eq!(
        network_queues::enqueue_outbound(
            &store,
            &[
                outbound.clone(),
                duplicate_outbound.clone(),
                other_outbound.clone()
            ]
        )
        .unwrap(),
        2
    );
    assert_eq!(
        network_queues::claim_outbound_for_target(&store, target, 16).unwrap(),
        vec![outbound.clone()]
    );
    assert_eq!(
        network_queues::claim_outbound_for_target(&store, other_target, 16).unwrap(),
        vec![other_outbound]
    );
    network_queues::delete_outbound(&store, &[outbound]).expect("delete queued outbound bytes");
    assert!(
        network_queues::claim_outbound_for_target(&store, target, 16)
            .unwrap()
            .is_empty()
    );

    let inbound = InboundNetworkRow::new(source, b"received bytes".to_vec());
    let duplicate_inbound = InboundNetworkRow::new(source, b"received bytes".to_vec());
    assert_eq!(
        network_queues::enqueue_inbound(&store, &[inbound.clone(), duplicate_inbound]).unwrap(),
        1
    );
    assert_eq!(
        network_queues::claim_inbound(&store, 16).unwrap(),
        vec![inbound.clone()]
    );
    network_queues::delete_inbound(&store, &[inbound]).expect("delete queued inbound bytes");
}
