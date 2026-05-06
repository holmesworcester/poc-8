use crate::core::crypto;
use crate::protocol::event_modules::identity::workspace;
use crate::protocol::event_modules::worker;
use crate::protocol::Protocol;

use super::{commands, schema};

// Invariant: receipt replays bootstrap then admin authorized grant without daemon.
#[test]
fn receipt_replays_bootstrap_then_admin_authorized_grant_without_daemon() {
    let protocol = Protocol::new();
    let receiver = Protocol::open_memory_store().expect("open receiver");
    let workspace_private_key = [7; crypto::ED25519_PRIVATE_KEY_BYTES];
    let workspace_public_key = crypto::ed25519_public_key(&workspace_private_key);
    let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 10,
        public_key: workspace_public_key,
        name: "Root".to_string(),
    })
    .expect("create workspace");
    let workspace_record = workspace.events[0].record().clone();
    let workspace_id = workspace.value.workspace_id;

    let bootstrap = commands::create_bootstrap(commands::CreateBootstrapAdmin {
        created_at_ms: 20,
        workspace_id,
        root_public_key: workspace_public_key,
        root_user_event_id: workspace_id,
        signer_private_key: workspace_private_key,
    })
    .expect("create bootstrap admin");
    let bootstrap_record = bootstrap.events[0].record().clone();
    let bootstrap_admin_id = bootstrap.value.admin_id;

    let grant = commands::sign_grant(commands::SignGrantAdmin {
        grant: commands::GrantAdmin {
            created_at_ms: 30,
            workspace_id,
            authority_admin_id: bootstrap_admin_id,
            target_user_event_id: workspace_id,
            target_user_public_key: workspace_public_key,
        },
        signer_event_id: bootstrap_admin_id,
        signer_private_key: workspace_private_key,
    })
    .expect("grant admin");
    let grant_record = grant.events[0].record().clone();
    let grant_admin_id = grant.value.signed_event_id;

    let admit = worker::run(
        &receiver,
        &protocol,
        worker::AdmitRecords {
            records: vec![grant_record, bootstrap_record, workspace_record],
        },
    )
    .expect("admit received records");
    assert_eq!(admit.inserted_events, 3);
    assert_eq!(admit.blocked_events, 2);
    assert_eq!(admit.applied_events, 1);

    let drained = worker::run(
        &receiver,
        &protocol,
        worker::DrainUntilIdle { batch_size: 10 },
    )
    .expect("drain ready events");
    assert_eq!(drained.applied_events, 2);

    let rows = receiver.table_rows(schema::ADMINS).expect("admin rows");
    assert_eq!(rows.len(), 2);
    let projected = rows
        .into_iter()
        .map(|(key, value)| schema::decode_admin_row(&key, &value).expect("admin row"))
        .collect::<Vec<_>>();
    assert!(projected
        .iter()
        .any(|row| row.admin_id == bootstrap_admin_id
            && row.authority_event_id == workspace_id
            && row.user_event_id == workspace_id));
    assert!(projected.iter().any(|row| row.admin_id == grant_admin_id
        && row.authority_event_id == bootstrap_admin_id
        && row.user_event_id == workspace_id));
    assert_ne!(bootstrap_admin_id, grant_admin_id);
    assert!(projected
        .iter()
        .all(|row| row.public_key == workspace_public_key));
}
