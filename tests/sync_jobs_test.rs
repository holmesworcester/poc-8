use topo::event_modules::connection::outbox;
use topo::event_modules::content::content_event;
use topo::event_modules::sync::{self, data, frame};
use topo::event_modules::Modules;
use topo::pipeline;
use topo::store::{CommandOutput, Store};

fn temp_store() -> (tempfile::TempDir, Store) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path().join("node.db")).unwrap();
    (tmp, store)
}

#[test]
fn sync_start_job_catches_up_negentropy_index_before_emitting_compare() {
    let (_tmp, store) = temp_store();
    let modules = Modules::new();
    let generated = modules.generate_content(&store, 5, 64).unwrap();
    pipeline::run_command(&store, &modules, generated).unwrap();
    assert_eq!(sync::negentropy::queries::cursor(&store).unwrap(), 0);

    let connection_id = [7; 32];
    let required_index_seq = store.max_applied_shared_seq().unwrap();
    pipeline::run_command(
        &store,
        &modules,
        CommandOutput::with_work(
            (),
            vec![sync::jobs::queue_start(connection_id, required_index_seq)],
        ),
    )
    .unwrap();

    let jobs = pipeline::drain_module_jobs(&store, &modules, 8).unwrap();
    assert_eq!(
        sync::negentropy::queries::cursor(&store).unwrap(),
        required_index_seq
    );
    assert!(jobs.jobs_run >= 2, "expected index catch-up and start jobs");
    assert_eq!(store.work_count().unwrap(), 0);

    let items = outbox::queries::all_items(&store).unwrap();
    assert_eq!(items.len(), 1);
    let decoded = frame::codec::decode(&items[0].event_bytes).unwrap();
    assert_eq!(decoded.items.len(), 1);
    match &decoded.items[0] {
        frame::types::SyncItem::Compare(compare) => {
            assert_eq!(compare.connection_id, connection_id);
            assert!(!compare.message.is_empty());
        }
        other => panic!("expected compare item, got {other:?}"),
    }
}

#[test]
fn inbound_data_work_admits_received_facts_through_pipeline() {
    let (_tmp, store) = temp_store();
    let modules = Modules::new();
    let connection_id = [9; 32];
    let generated = content_event::commands::generate(1, 3, 48).unwrap();
    let event_bytes = generated
        .events
        .iter()
        .map(|record| record.canonical_bytes.clone())
        .collect::<Vec<_>>();
    let encoded_frame = frame::codec::encode(&frame::types::Frame {
        more: false,
        items: vec![frame::types::SyncItem::Data(data::types::DataEvent {
            connection_id,
            items: event_bytes,
        })],
    });

    pipeline::run_command(
        &store,
        &modules,
        CommandOutput::with_work(
            (),
            vec![sync::jobs::queue_inbound_frame(
                connection_id,
                0,
                encoded_frame,
            )],
        ),
    )
    .unwrap();

    let jobs = pipeline::drain_module_jobs(&store, &modules, 8).unwrap();
    assert_eq!(jobs.received_events, 3);
    assert_eq!(jobs.inserted_events, 3);
    assert_eq!(jobs.applied_events, 3);
    assert_eq!(store.event_count().unwrap(), 3);
    assert_eq!(store.work_count().unwrap(), 0);
}
