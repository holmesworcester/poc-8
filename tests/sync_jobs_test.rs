use topo::event_modules::connection::outbox;
use topo::event_modules::content::content_event;
use topo::event_modules::sync;
use topo::event_modules::sync::data::types::DataEvent;
use topo::event_modules::sync::frame::types::{Frame, SyncItem};
use topo::event_modules::sync::need_id::types::NeedIdEvent;
use topo::event_modules::Modules;
use topo::pipeline;
use topo::store::{event_id, Store};

fn temp_store() -> (tempfile::TempDir, Store) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path().join("node.db")).unwrap();
    (tmp, store)
}

#[test]
fn queued_start_catches_up_index_before_emitting_compare_frame() {
    let (_tmp, store) = temp_store();
    let modules = Modules::new();
    let generated = modules.generate_content(&store, 5, 64).unwrap();
    pipeline::run_command(&store, &modules, generated).unwrap();

    let connection_id = [7; 32];
    let required_index_seq = store.max_applied_shared_seq().unwrap();
    assert_eq!(required_index_seq, 5);
    assert_eq!(sync::negentropy::queries::cursor(&store).unwrap(), 0);

    store
        .insert_table_rows(vec![sync::jobs::queue_start(
            connection_id,
            required_index_seq,
        )])
        .unwrap();
    let report = pipeline::drain_module_jobs(&store, &modules, 8).unwrap();

    assert_eq!(report.jobs_run, 2);
    assert_eq!(sync::negentropy::queries::cursor(&store).unwrap(), 5);
    assert_eq!(
        store
            .table_row_count(sync::negentropy::tables::INDEX)
            .unwrap(),
        5
    );
    assert_eq!(store.table_row_count(sync::jobs::tables::WORK).unwrap(), 0);

    let items = outbox::queries::items_for_connection(&store, connection_id).unwrap();
    assert_eq!(items.len(), 1);
    let frame = sync::frame::codec::decode(&items[0].event_bytes).unwrap();
    assert_eq!(frame.items.len(), 1);
    let SyncItem::Compare(compare) = &frame.items[0] else {
        panic!("expected compare frame");
    };
    assert_eq!(compare.connection_id, connection_id);
    assert!(compare.sender_is_initiator);
    assert!(!compare.message.is_empty());
}

#[test]
fn queued_data_frame_admits_received_event_facts() {
    let (_tmp, store) = temp_store();
    let modules = Modules::new();
    let connection_id = [9; 32];
    let generated = content_event::commands::generate(1, 3, 48).unwrap();
    let event_bytes = generated
        .events
        .iter()
        .map(|record| record.canonical_bytes.clone())
        .collect::<Vec<_>>();
    let frame = sync::frame::codec::encode(&Frame {
        more: false,
        items: vec![SyncItem::Data(DataEvent {
            connection_id,
            items: event_bytes,
        })],
    });

    store
        .insert_table_rows(vec![sync::jobs::queue_inbound_frame(
            connection_id,
            0,
            frame,
        )])
        .unwrap();
    let report = pipeline::drain_module_jobs(&store, &modules, 8).unwrap();

    assert_eq!(report.jobs_run, 2);
    assert_eq!(report.received_events, 3);
    assert_eq!(report.inserted_events, 3);
    assert_eq!(report.applied_events, 3);
    assert_eq!(store.event_count().unwrap(), 3);
    assert_eq!(sync::negentropy::queries::cursor(&store).unwrap(), 3);
    assert_eq!(store.table_row_count(sync::jobs::tables::WORK).unwrap(), 0);
}

#[test]
fn queued_need_id_uses_index_context_to_emit_requested_data() {
    let (_tmp, store) = temp_store();
    let modules = Modules::new();
    let generated = modules.generate_content(&store, 2, 96).unwrap();
    let event_bytes = generated.events[0].canonical_bytes.clone();
    let requested_id = event_id(&event_bytes);
    pipeline::run_command(&store, &modules, generated).unwrap();

    let connection_id = [11; 32];
    let required_index_seq = store.max_applied_shared_seq().unwrap();
    let frame = sync::frame::codec::encode(&Frame {
        more: false,
        items: vec![SyncItem::NeedId(NeedIdEvent {
            connection_id,
            id: requested_id,
        })],
    });
    store
        .insert_table_rows(vec![sync::jobs::queue_inbound_frame(
            connection_id,
            required_index_seq,
            frame,
        )])
        .unwrap();

    let report = pipeline::drain_module_jobs(&store, &modules, 8).unwrap();

    assert_eq!(report.jobs_run, 2);
    assert_eq!(report.sent_events, 1);
    assert_eq!(sync::negentropy::queries::cursor(&store).unwrap(), 2);
    assert_eq!(store.table_row_count(sync::jobs::tables::WORK).unwrap(), 0);

    let items = outbox::queries::items_for_connection(&store, connection_id).unwrap();
    assert_eq!(items.len(), 1);
    let frame = sync::frame::codec::decode(&items[0].event_bytes).unwrap();
    assert_eq!(frame.items.len(), 1);
    let SyncItem::Data(data) = &frame.items[0] else {
        panic!("expected data frame");
    };
    assert_eq!(data.connection_id, connection_id);
    assert_eq!(data.items, vec![event_bytes]);
}
