use crate::core::crypto;
use crate::protocol::event_modules::identity::{user_invite, workspace};
use crate::protocol::event_modules::worker;
use crate::protocol::Protocol;

use super::commands::{self, CreateUser};
use super::schema;

#[test]
fn admits_workspace_invite_user_join_flow_and_projects_rows() {
    let protocol = Protocol::new();
    let store = Protocol::open_memory_store().expect("open protocol store");
    let workspace_private_key = [7; 32];
    let workspace_public_key = crypto::ed25519_public_key(&workspace_private_key);
    let invite_private_key = [8; 32];
    let invite_public_key = crypto::ed25519_public_key(&invite_private_key);
    let user_public_key = crypto::ed25519_public_key(&[9; 32]);

    let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 1,
        public_key: workspace_public_key,
        disappearing_ttl_minutes: 0,
        name: "Workspace".to_string(),
    })
    .expect("create workspace");
    let (workspace_created, _) =
        worker::run(&store, &protocol, workspace).expect("admit workspace");

    let user_invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
        created_at_ms: 2,
        public_key: invite_public_key,
        workspace_id: workspace_created.workspace_id,
        authority_event_id: workspace_created.workspace_id,
        signer_event_id: workspace_created.workspace_id,
        signer_private_key: workspace_private_key,
    })
    .expect("create user_invite");
    let (invite_created, _) =
        worker::run(&store, &protocol, user_invite).expect("admit user_invite");

    let user = commands::create(CreateUser {
        created_at_ms: 3,
        workspace_id: workspace_created.workspace_id,
        public_key: user_public_key,
        username: "alice".to_string(),
        user_invite_event_id: invite_created.user_invite_id,
        user_invite_private_key: invite_private_key,
    })
    .expect("create user");
    let (user_created, _) = worker::run(&store, &protocol, user).expect("admit user");

    let invite_row_key = user_invite::schema::user_invite_key(
        &workspace_created.workspace_id,
        &invite_created.user_invite_id,
    );
    let invite_row = store
        .table_row(user_invite::schema::USER_INVITES, &invite_row_key)
        .expect("load invite row")
        .expect("invite row exists");
    let invite_row = user_invite::schema::decode_user_invite_row(&invite_row_key, &invite_row)
        .expect("decode invite row");
    assert_eq!(invite_row.public_key, invite_public_key);

    let user_row_key = schema::user_key(&workspace_created.workspace_id, &user_created.user_id);
    let user_row = store
        .table_row(schema::USERS, &user_row_key)
        .expect("load user row")
        .expect("user row exists");
    let user_row = schema::decode_user_row(&user_row_key, &user_row).expect("decode user row");
    assert_eq!(user_row.workspace_id, workspace_created.workspace_id);
    assert_eq!(user_row.user_invite_id, invite_created.user_invite_id);
    assert_eq!(user_row.public_key, user_public_key);
    assert_eq!(user_row.username, "alice");
}

#[test]
fn admission_rejects_user_signed_by_key_not_authorized_by_invite() {
    let protocol = Protocol::new();
    let store = Protocol::open_memory_store().expect("open protocol store");
    let workspace_private_key = [7; 32];
    let workspace_public_key = crypto::ed25519_public_key(&workspace_private_key);
    let invite_private_key = [8; 32];
    let invite_public_key = crypto::ed25519_public_key(&invite_private_key);

    let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 1,
        public_key: workspace_public_key,
        disappearing_ttl_minutes: 0,
        name: "Workspace".to_string(),
    })
    .expect("create workspace");
    let (workspace_created, _) =
        worker::run(&store, &protocol, workspace).expect("admit workspace");
    let user_invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
        created_at_ms: 2,
        public_key: invite_public_key,
        workspace_id: workspace_created.workspace_id,
        authority_event_id: workspace_created.workspace_id,
        signer_event_id: workspace_created.workspace_id,
        signer_private_key: workspace_private_key,
    })
    .expect("create user_invite");
    let (invite_created, _) =
        worker::run(&store, &protocol, user_invite).expect("admit user_invite");

    let user = commands::create(CreateUser {
        created_at_ms: 3,
        workspace_id: workspace_created.workspace_id,
        public_key: crypto::ed25519_public_key(&[9; 32]),
        username: "alice".to_string(),
        user_invite_event_id: invite_created.user_invite_id,
        user_invite_private_key: [10; 32],
    })
    .expect("create user with wrong signer key");

    let err = worker::run(&store, &protocol, user)
        .expect_err("admission must reject wrong user signer key");

    assert!(
        err.contains("signed user signer key does not match user_invite public key"),
        "{err}"
    );
}

#[test]
fn join_store_receives_shared_workspace_and_invite_records_then_creates_user() {
    let protocol = Protocol::new();
    let creator_store = Protocol::open_memory_store().expect("open creator store");
    let join_store = Protocol::open_memory_store().expect("open join store");
    let workspace_private_key = [7; 32];
    let workspace_public_key = crypto::ed25519_public_key(&workspace_private_key);
    let invite_private_key = [8; 32];
    let invite_public_key = crypto::ed25519_public_key(&invite_private_key);
    let user_public_key = crypto::ed25519_public_key(&[9; 32]);

    let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 1,
        public_key: workspace_public_key,
        disappearing_ttl_minutes: 0,
        name: "Workspace".to_string(),
    })
    .expect("create workspace");
    let workspace_records = workspace
        .events
        .iter()
        .map(|event| event.record().clone())
        .collect::<Vec<_>>();
    let (workspace_created, _) =
        worker::run(&creator_store, &protocol, workspace).expect("admit workspace");

    let user_invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
        created_at_ms: 2,
        public_key: invite_public_key,
        workspace_id: workspace_created.workspace_id,
        authority_event_id: workspace_created.workspace_id,
        signer_event_id: workspace_created.workspace_id,
        signer_private_key: workspace_private_key,
    })
    .expect("create user_invite");
    let invite_records = user_invite
        .events
        .iter()
        .map(|event| event.record().clone())
        .collect::<Vec<_>>();
    let (invite_created, _) =
        worker::run(&creator_store, &protocol, user_invite).expect("admit user_invite");

    let blocked = worker::run(
        &join_store,
        &protocol,
        worker::AdmitRecords {
            records: invite_records,
        },
    )
    .expect("admit invite before workspace");
    assert_eq!(blocked.blocked_events, 1);

    worker::run(
        &join_store,
        &protocol,
        worker::AdmitRecords {
            records: workspace_records,
        },
    )
    .expect("admit workspace");
    worker::run(
        &join_store,
        &protocol,
        worker::DrainUntilIdle { batch_size: 16 },
    )
    .expect("drain unblocked invite");

    let user = commands::create(CreateUser {
        created_at_ms: 3,
        workspace_id: workspace_created.workspace_id,
        public_key: user_public_key,
        username: "alice".to_string(),
        user_invite_event_id: invite_created.user_invite_id,
        user_invite_private_key: invite_private_key,
    })
    .expect("create user");
    let (user_created, _) = worker::run(&join_store, &protocol, user).expect("admit user");

    let user_row_key = schema::user_key(&workspace_created.workspace_id, &user_created.user_id);
    let user_row = join_store
        .table_row(schema::USERS, &user_row_key)
        .expect("load user row")
        .expect("user row exists");
    let user_row = schema::decode_user_row(&user_row_key, &user_row).expect("decode user row");
    assert_eq!(user_row.workspace_id, workspace_created.workspace_id);
    assert_eq!(user_row.user_invite_id, invite_created.user_invite_id);
    assert_eq!(user_row.username, "alice");
}
