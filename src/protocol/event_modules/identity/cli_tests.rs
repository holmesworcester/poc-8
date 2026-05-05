use crate::core::crypto;
use crate::protocol::event_modules::identity::{
    admin, device_invite, endpoint_shared, signed, user, user_invite, workspace,
};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::{EventId, EventRecord};
use crate::protocol::event_modules::worker::{self, CommandOutput};
use crate::protocol::Protocol;

#[test]
fn identity_cli_create_workspace_builds_creator_graph_and_read_surfaces() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = tmp.path().join("identity.db");

    let created = run_protocol_cli(
        &db,
        &[
            "create-workspace",
            "Alpha",
            "--username",
            "alice",
            "--devicename",
            "alice-laptop",
        ],
    );
    let workspace_id = line_value(&created, "workspace_id");
    let user_id = line_value(&created, "user_id");
    assert!(!line_value(&created, "admin_id").is_empty());

    let workspaces = run_protocol_cli(&db, &["workspaces"]);
    assert!(workspaces.contains("Alpha"), "{workspaces}");
    assert!(workspaces.contains(&workspace_id), "{workspaces}");

    let users = run_protocol_cli(&db, &["users", &workspace_id]);
    assert!(users.contains("alice"), "{users}");
    assert!(users.contains(&user_id), "{users}");

    let peers = run_protocol_cli(&db, &["peers", &workspace_id]);
    assert!(peers.contains("alice-laptop"), "{peers}");
    assert!(peers.contains(&format!("user_id={user_id}")), "{peers}");

    let identity = run_protocol_cli(&db, &["identity"]);
    assert!(identity.contains("endpoint_id:"), "{identity}");
    assert!(identity.contains(&workspace_id), "{identity}");
    assert!(identity.contains(&user_id), "{identity}");
}

#[test]
fn identity_cli_workspace_invite_and_link_create_scoped_real_invite_events() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = tmp.path().join("identity.db");

    let created = run_protocol_cli(
        &db,
        &[
            "create-workspace",
            "Alpha",
            "--username",
            "alice",
            "--devicename",
            "alice-laptop",
        ],
    );
    let workspace_id = line_value(&created, "workspace_id");

    let user_invite_link = run_protocol_cli(
        &db,
        &[
            "invite",
            "--workspace",
            &workspace_id,
            "--public-addr",
            "127.0.0.1:41000",
        ],
    );
    let parsed = super::invite::commands::parse(user_invite_link.trim()).expect("parse invite");
    assert_eq!(
        super::invite::commands::encode_hex(&parsed.workspace_id),
        workspace_id
    );

    let device_link = run_protocol_cli(
        &db,
        &["link", &workspace_id, "--public-addr", "127.0.0.1:41001"],
    );
    let parsed_link = super::invite::commands::parse(device_link.trim()).expect("parse link");
    assert_eq!(
        super::invite::commands::encode_hex(&parsed_link.workspace_id),
        workspace_id
    );

    let store = Protocol::open_store(&db).expect("open store");
    assert_eq!(row_count(&store, user_invite::schema::USER_INVITES), 2);
    assert_eq!(row_count(&store, device_invite::schema::DEVICE_INVITES), 2);
}

#[test]
fn unknown_signed_identity_payloads_are_rejected_at_admission() {
    let signed = signed::commands::sign_payload([1; 32], &[2; 32], vec![250, 1, 2, 3])
        .expect("sign unknown payload");

    let err = crate::protocol::event_modules::record_from_bytes(
        signed.events[0].record().canonical_bytes.clone(),
    )
    .expect_err("unknown signed payload must not be admitted");

    assert_eq!(err, "signed envelope inner type 250 has no identity record");
}

fn run_protocol_cli(db: &std::path::Path, args: &[&str]) -> String {
    let mut context = crate::protocol::cli::Context::open(db).expect("open cli context");
    let command_args = args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
    let output = crate::core::cli::run(
        &crate::protocol::cli::commands(),
        &mut context,
        &command_args,
    )
    .unwrap_or_else(|err| panic!("cli failed for {args:?}: {err}"));
    output.lines.join("\n")
}

fn line_value(output: &str, key: &str) -> String {
    let prefix = format!("{key}: ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing `{key}:` in output:\n{output}"))
        .to_string()
}

#[test]
fn bootstrap_two_users_and_two_endpoints_replay_without_daemon() {
    let protocol = Protocol::new();
    let creator = Protocol::open_memory_store().expect("open creator");
    let receiver = Protocol::open_memory_store().expect("open receiver");
    let workspace_private_key = [7; 32];
    let workspace_public_key = crypto::ed25519_public_key(&workspace_private_key);

    let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 1,
        public_key: workspace_public_key,
        name: "Workspace".to_string(),
    })
    .expect("create workspace");
    let workspace_id = workspace.value.workspace_id;
    let workspace_records = admit(&creator, &protocol, workspace);

    let bootstrap = admin::commands::create_bootstrap(admin::commands::CreateBootstrapAdmin {
        created_at_ms: 2,
        workspace_id,
        root_public_key: workspace_public_key,
        root_user_event_id: workspace_id,
        signer_private_key: workspace_private_key,
    })
    .expect("create bootstrap admin");
    let bootstrap_admin_id = bootstrap.value.admin_id;
    let bootstrap_records = admit(&creator, &protocol, bootstrap);

    let alice = create_user(
        &creator,
        &protocol,
        UserInput {
            workspace_id,
            workspace_private_key,
            timestamp: 10,
            username: "alice",
            invite_private_key: [8; 32],
            user_private_key: [18; 32],
        },
    );
    let bob = create_user(
        &creator,
        &protocol,
        UserInput {
            workspace_id,
            workspace_private_key,
            timestamp: 20,
            username: "bob",
            invite_private_key: [9; 32],
            user_private_key: [19; 32],
        },
    );

    let alice_join = share_endpoint(
        &creator,
        &protocol,
        EndpointJoinInput {
            workspace_id,
            user_id: alice.user_id,
            user_invite_id: Some(alice.user_invite_id),
            signer_event_id: alice.user_id,
            signer_private_key: alice.user_private_key,
            endpoint_private_key: [31; 32],
            device_name: "alice-laptop",
            timestamp: 30,
            device_invite_private_key: [40; 32],
        },
    );
    let alice_second_join = share_endpoint(
        &creator,
        &protocol,
        EndpointJoinInput {
            workspace_id,
            user_id: alice.user_id,
            user_invite_id: None,
            signer_event_id: alice_join.endpoint_shared_id,
            signer_private_key: alice_join.endpoint_private_key,
            endpoint_private_key: [33; 32],
            device_name: "alice-tablet",
            timestamp: 35,
            device_invite_private_key: [42; 32],
        },
    );
    let bob_join = share_endpoint(
        &creator,
        &protocol,
        EndpointJoinInput {
            workspace_id,
            user_id: bob.user_id,
            user_invite_id: Some(bob.user_invite_id),
            signer_event_id: bob.user_id,
            signer_private_key: bob.user_private_key,
            endpoint_private_key: [32; 32],
            device_name: "bob-phone",
            timestamp: 40,
            device_invite_private_key: [41; 32],
        },
    );

    let received = reversed_records(vec![
        workspace_records,
        bootstrap_records,
        alice.records,
        bob.records,
        alice_join.records,
        alice_second_join.records,
        bob_join.records,
    ]);
    let inserted = received.len();
    let report = worker::run(
        &receiver,
        &protocol,
        worker::AdmitRecords { records: received },
    )
    .expect("admit out-of-order identity graph");
    assert_eq!(report.inserted_events, inserted);
    assert_eq!(report.applied_events, 1);
    assert!(
        report.blocked_events > 0,
        "out-of-order receipt should block children until dependencies apply"
    );

    let drained = worker::run(
        &receiver,
        &protocol,
        worker::DrainUntilIdle {
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .expect("drain ready identity graph");
    assert_eq!(drained.applied_events, inserted - 1);

    let statuses = event_schema::status_counts(&receiver).expect("status counts");
    assert_eq!(statuses.applied, inserted);
    assert_eq!(statuses.blocked, 0);
    assert_eq!(statuses.rejected, 0);
    assert_eq!(statuses.blocked_edges, 0);

    assert_eq!(row_count(&receiver, admin::schema::ADMINS), 1);
    assert_eq!(row_count(&receiver, user_invite::schema::USER_INVITES), 2);
    assert_eq!(row_count(&receiver, user::schema::USERS), 2);
    assert_eq!(
        row_count(&receiver, device_invite::schema::DEVICE_INVITES),
        3
    );
    assert_eq!(
        row_count(&receiver, endpoint_shared::schema::ENDPOINT_SHARED),
        3
    );
    assert_eq!(
        row_count(&receiver, endpoint_shared::schema::ENDPOINT_MEMBERSHIPS),
        3
    );

    assert_admin(
        &receiver,
        workspace_id,
        bootstrap_admin_id,
        workspace_public_key,
    );
    assert_user(&receiver, workspace_id, alice.user_id, "alice");
    assert_user(&receiver, workspace_id, bob.user_id, "bob");
    assert_membership(
        &receiver,
        workspace_id,
        alice_join.endpoint_id,
        alice.user_id,
    );
    assert_membership(
        &receiver,
        workspace_id,
        alice_second_join.endpoint_id,
        alice.user_id,
    );
    assert_membership(&receiver, workspace_id, bob_join.endpoint_id, bob.user_id);

    let duplicate = endpoint_shared::commands::share_endpoint(
        &receiver,
        endpoint_shared::commands::ShareEndpoint {
            created_at_ms: 50,
            workspace_id,
            user_authority_event_id: alice.user_id,
            endpoint_id: alice_join.endpoint_id,
            signing_public_key: crypto::ed25519_public_key(&alice_join.endpoint_private_key),
            device_name: "alice-second-join".to_string(),
            device_invite_id: alice_join.device_invite_id,
            device_invite_private_key: alice_join.device_invite_private_key,
        },
    )
    .expect_err("same endpoint cannot join same workspace twice");
    assert_eq!(duplicate, "endpoint is already joined to workspace");
}

#[test]
fn same_user_client_can_link_multiple_workspaces_but_authority_does_not_cross() {
    let protocol = Protocol::new();
    let store = Protocol::open_memory_store().expect("open store");
    let workspace_a_private_key = [71; 32];
    let workspace_b_private_key = [72; 32];
    let shared_user_private_key = [73; 32];
    let shared_endpoint_private_key = [74; 32];

    let workspace_a = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 1,
        public_key: crypto::ed25519_public_key(&workspace_a_private_key),
        name: "Workspace A".to_string(),
    })
    .expect("create workspace A");
    let workspace_a_id = workspace_a.value.workspace_id;
    admit(&store, &protocol, workspace_a);

    let workspace_b = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 2,
        public_key: crypto::ed25519_public_key(&workspace_b_private_key),
        name: "Workspace B".to_string(),
    })
    .expect("create workspace B");
    let workspace_b_id = workspace_b.value.workspace_id;
    admit(&store, &protocol, workspace_b);

    let alice_a = create_user(
        &store,
        &protocol,
        UserInput {
            workspace_id: workspace_a_id,
            workspace_private_key: workspace_a_private_key,
            timestamp: 10,
            username: "alice",
            invite_private_key: [81; 32],
            user_private_key: shared_user_private_key,
        },
    );
    let alice_b = create_user(
        &store,
        &protocol,
        UserInput {
            workspace_id: workspace_b_id,
            workspace_private_key: workspace_b_private_key,
            timestamp: 20,
            username: "alice",
            invite_private_key: [82; 32],
            user_private_key: shared_user_private_key,
        },
    );

    let join_a = share_endpoint(
        &store,
        &protocol,
        EndpointJoinInput {
            workspace_id: workspace_a_id,
            user_id: alice_a.user_id,
            user_invite_id: Some(alice_a.user_invite_id),
            signer_event_id: alice_a.user_id,
            signer_private_key: alice_a.user_private_key,
            endpoint_private_key: shared_endpoint_private_key,
            device_name: "alice-laptop-a",
            timestamp: 30,
            device_invite_private_key: [83; 32],
        },
    );
    let join_b = share_endpoint(
        &store,
        &protocol,
        EndpointJoinInput {
            workspace_id: workspace_b_id,
            user_id: alice_b.user_id,
            user_invite_id: Some(alice_b.user_invite_id),
            signer_event_id: alice_b.user_id,
            signer_private_key: alice_b.user_private_key,
            endpoint_private_key: shared_endpoint_private_key,
            device_name: "alice-laptop-b",
            timestamp: 40,
            device_invite_private_key: [84; 32],
        },
    );

    assert_eq!(join_a.endpoint_id, join_b.endpoint_id);
    assert_membership(&store, workspace_a_id, join_a.endpoint_id, alice_a.user_id);
    assert_membership(&store, workspace_b_id, join_b.endpoint_id, alice_b.user_id);

    let cross_workspace_invite = device_invite::commands::create_with_private_key(
        device_invite::commands::CreateDeviceInvite {
            created_at_ms: 50,
            workspace_id: workspace_b_id,
            user_authority_event_id: alice_b.user_id,
            user_invite_event_id: None,
            signer_event_id: join_a.endpoint_shared_id,
            signer_private_key: join_a.endpoint_private_key,
        },
        [85; 32],
    )
    .expect("create cross-workspace invite");
    let err = worker::run(&store, &protocol, cross_workspace_invite)
        .expect_err("workspace A endpoint_shared must not authorize workspace B invite");
    assert!(
        err.contains("endpoint_shared-signed device_invite workspace does not match signer"),
        "{err}"
    );

    let cross_workspace_share = endpoint_shared::commands::share_endpoint(
        &store,
        endpoint_shared::commands::ShareEndpoint {
            created_at_ms: 60,
            workspace_id: workspace_b_id,
            user_authority_event_id: alice_b.user_id,
            endpoint_id: crypto::ed25519_public_key(&[86; 32]),
            signing_public_key: crypto::ed25519_public_key(&[86; 32]),
            device_name: "cross-workspace".to_string(),
            device_invite_id: join_a.device_invite_id,
            device_invite_private_key: join_a.device_invite_private_key,
        },
    )
    .expect("create cross-workspace endpoint_shared");
    let err = worker::run(&store, &protocol, cross_workspace_share)
        .expect_err("workspace A device_invite must not link workspace B endpoint");
    assert!(
        err.contains("endpoint_shared workspace does not match device_invite"),
        "{err}"
    );
}

#[test]
fn unsigned_device_invite_bytes_are_not_admissible_protocol_events() {
    let raw = device_invite::types::DeviceInviteEvent {
        created_at_ms: 1,
        workspace_id: [1; 32],
        user_authority_event_id: [2; 32],
        user_invite_event_id: Some([3; 32]),
        public_key: crypto::ed25519_public_key(&[4; 32]),
    };

    let err = crate::protocol::event_modules::record_from_bytes(device_invite::codec::encode(&raw))
        .expect_err("unsigned device_invite must not decode as a protocol event");

    assert_eq!(err, "device_invite must be signed");
}

#[test]
fn admin_user_endpoint_authorizes_invites_per_workspace_without_cross_authorizing() {
    let protocol = Protocol::new();
    let store = Protocol::open_memory_store().expect("open store");
    let workspace_a_private_key = [7; 32];
    let workspace_b_private_key = [17; 32];
    let admin_user_private_key = [18; 32];
    let admin_endpoint_private_key = [31; 32];
    let admin_endpoint_id = crypto::ed25519_public_key(&admin_endpoint_private_key);

    let workspace_a = create_workspace_with_bootstrap_admin(
        &store,
        &protocol,
        1,
        workspace_a_private_key,
        "Workspace A",
    );
    let workspace_b = create_workspace_with_bootstrap_admin(
        &store,
        &protocol,
        101,
        workspace_b_private_key,
        "Workspace B",
    );

    let admin_user_a = create_user(
        &store,
        &protocol,
        UserInput {
            workspace_id: workspace_a.workspace_id,
            workspace_private_key: workspace_a_private_key,
            timestamp: 10,
            username: "same-admin-user",
            invite_private_key: [8; 32],
            user_private_key: admin_user_private_key,
        },
    );
    let admin_user_b = create_user(
        &store,
        &protocol,
        UserInput {
            workspace_id: workspace_b.workspace_id,
            workspace_private_key: workspace_b_private_key,
            timestamp: 110,
            username: "same-admin-user",
            invite_private_key: [9; 32],
            user_private_key: admin_user_private_key,
        },
    );

    let admin_a = grant_admin(
        &store,
        &protocol,
        AdminGrantInput {
            created_at_ms: 20,
            workspace_id: workspace_a.workspace_id,
            authority_admin_id: workspace_a.bootstrap_admin_id,
            authority_private_key: workspace_a_private_key,
            target_user_event_id: admin_user_a.user_id,
            target_user_public_key: admin_user_a.public_key,
        },
    );
    let admin_b = grant_admin(
        &store,
        &protocol,
        AdminGrantInput {
            created_at_ms: 120,
            workspace_id: workspace_b.workspace_id,
            authority_admin_id: workspace_b.bootstrap_admin_id,
            authority_private_key: workspace_b_private_key,
            target_user_event_id: admin_user_b.user_id,
            target_user_public_key: admin_user_b.public_key,
        },
    );

    let endpoint_a = share_endpoint(
        &store,
        &protocol,
        EndpointJoinInput {
            workspace_id: workspace_a.workspace_id,
            user_id: admin_user_a.user_id,
            user_invite_id: Some(admin_user_a.user_invite_id),
            signer_event_id: admin_user_a.user_id,
            signer_private_key: admin_user_private_key,
            endpoint_private_key: admin_endpoint_private_key,
            device_name: "admin-laptop-a",
            timestamp: 30,
            device_invite_private_key: [40; 32],
        },
    );
    let endpoint_b = share_endpoint(
        &store,
        &protocol,
        EndpointJoinInput {
            workspace_id: workspace_b.workspace_id,
            user_id: admin_user_b.user_id,
            user_invite_id: Some(admin_user_b.user_invite_id),
            signer_event_id: admin_user_b.user_id,
            signer_private_key: admin_user_private_key,
            endpoint_private_key: admin_endpoint_private_key,
            device_name: "admin-laptop-b",
            timestamp: 130,
            device_invite_private_key: [41; 32],
        },
    );

    let invited_a = create_user_from_admin_invite(
        &store,
        &protocol,
        AdminInviteUserInput {
            workspace_id: workspace_a.workspace_id,
            authority_admin_id: admin_a,
            signer_endpoint_shared_id: endpoint_a.endpoint_shared_id,
            signer_endpoint_private_key: admin_endpoint_private_key,
            timestamp: 40,
            username: "invited-a",
            invite_private_key: [50; 32],
            user_private_key: [60; 32],
        },
    );
    let invited_b = create_user_from_admin_invite(
        &store,
        &protocol,
        AdminInviteUserInput {
            workspace_id: workspace_b.workspace_id,
            authority_admin_id: admin_b,
            signer_endpoint_shared_id: endpoint_b.endpoint_shared_id,
            signer_endpoint_private_key: admin_endpoint_private_key,
            timestamp: 140,
            username: "invited-b",
            invite_private_key: [51; 32],
            user_private_key: [61; 32],
        },
    );

    assert_user(
        &store,
        workspace_a.workspace_id,
        invited_a.user_id,
        "invited-a",
    );
    assert_user(
        &store,
        workspace_b.workspace_id,
        invited_b.user_id,
        "invited-b",
    );
    assert_membership(
        &store,
        workspace_a.workspace_id,
        admin_endpoint_id,
        admin_user_a.user_id,
    );
    assert_membership(
        &store,
        workspace_b.workspace_id,
        admin_endpoint_id,
        admin_user_b.user_id,
    );

    let cross_workspace_invite =
        user_invite::commands::create(user_invite::commands::CreateUserInvite {
            created_at_ms: 150,
            public_key: crypto::ed25519_public_key(&[52; 32]),
            workspace_id: workspace_b.workspace_id,
            authority_event_id: admin_a,
            signer_event_id: endpoint_b.endpoint_shared_id,
            signer_private_key: admin_endpoint_private_key,
        })
        .expect("create cross-workspace invite attempt");
    let err = worker::run(&store, &protocol, cross_workspace_invite)
        .expect_err("workspace A admin must not authorize workspace B invite");
    assert!(
        err.contains("user_invite admin authority belongs to a different workspace"),
        "{err}"
    );

    let cross_workspace_grant = admin::commands::sign_grant(admin::commands::SignGrantAdmin {
        grant: admin::commands::GrantAdmin {
            created_at_ms: 160,
            workspace_id: workspace_b.workspace_id,
            authority_admin_id: admin_a,
            target_user_event_id: admin_user_b.user_id,
            target_user_public_key: admin_user_b.public_key,
        },
        signer_event_id: admin_a,
        signer_private_key: admin_user_private_key,
    })
    .expect("create cross-workspace admin grant attempt");
    let err = worker::run(&store, &protocol, cross_workspace_grant)
        .expect_err("workspace A admin must not authorize workspace B admin grant");
    assert!(
        err.contains("admin authority belongs to a different workspace"),
        "{err}"
    );

    assert_eq!(row_count(&store, admin::schema::ADMINS), 4);
    assert_eq!(row_count(&store, user_invite::schema::USER_INVITES), 4);
    assert_eq!(row_count(&store, user::schema::USERS), 4);
    assert_eq!(
        row_count(&store, endpoint_shared::schema::ENDPOINT_SHARED),
        2
    );
    assert_eq!(
        row_count(&store, endpoint_shared::schema::ENDPOINT_MEMBERSHIPS),
        2
    );
}

struct WorkspaceBootstrap {
    workspace_id: EventId,
    bootstrap_admin_id: EventId,
}

struct CreatedUser {
    user_id: EventId,
    user_invite_id: EventId,
    public_key: [u8; 32],
    user_private_key: [u8; 32],
    records: Vec<EventRecord>,
}

struct UserInput {
    workspace_id: EventId,
    workspace_private_key: [u8; 32],
    timestamp: u64,
    username: &'static str,
    invite_private_key: [u8; 32],
    user_private_key: [u8; 32],
}

struct EndpointJoin {
    endpoint_shared_id: EventId,
    endpoint_id: [u8; 32],
    device_invite_id: EventId,
    device_invite_private_key: [u8; 32],
    endpoint_private_key: [u8; 32],
    records: Vec<EventRecord>,
}

struct EndpointJoinInput {
    workspace_id: EventId,
    user_id: EventId,
    user_invite_id: Option<EventId>,
    signer_event_id: EventId,
    signer_private_key: [u8; 32],
    endpoint_private_key: [u8; 32],
    device_name: &'static str,
    timestamp: u64,
    device_invite_private_key: [u8; 32],
}

struct AdminGrantInput {
    created_at_ms: u64,
    workspace_id: EventId,
    authority_admin_id: EventId,
    authority_private_key: [u8; 32],
    target_user_event_id: EventId,
    target_user_public_key: [u8; 32],
}

struct AdminInviteUserInput {
    workspace_id: EventId,
    authority_admin_id: EventId,
    signer_endpoint_shared_id: EventId,
    signer_endpoint_private_key: [u8; 32],
    timestamp: u64,
    username: &'static str,
    invite_private_key: [u8; 32],
    user_private_key: [u8; 32],
}

fn create_workspace_with_bootstrap_admin(
    store: &crate::core::store::Store,
    protocol: &Protocol,
    timestamp: u64,
    workspace_private_key: [u8; 32],
    name: &str,
) -> WorkspaceBootstrap {
    let workspace_public_key = crypto::ed25519_public_key(&workspace_private_key);
    let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: timestamp,
        public_key: workspace_public_key,
        name: name.to_string(),
    })
    .expect("create workspace");
    let workspace_id = workspace.value.workspace_id;
    admit(store, protocol, workspace);

    let bootstrap = admin::commands::create_bootstrap(admin::commands::CreateBootstrapAdmin {
        created_at_ms: timestamp + 1,
        workspace_id,
        root_public_key: workspace_public_key,
        root_user_event_id: workspace_id,
        signer_private_key: workspace_private_key,
    })
    .expect("create bootstrap admin");
    let bootstrap_admin_id = bootstrap.value.admin_id;
    admit(store, protocol, bootstrap);

    WorkspaceBootstrap {
        workspace_id,
        bootstrap_admin_id,
    }
}

fn grant_admin(
    store: &crate::core::store::Store,
    protocol: &Protocol,
    input: AdminGrantInput,
) -> EventId {
    let grant = admin::commands::sign_grant(admin::commands::SignGrantAdmin {
        grant: admin::commands::GrantAdmin {
            created_at_ms: input.created_at_ms,
            workspace_id: input.workspace_id,
            authority_admin_id: input.authority_admin_id,
            target_user_event_id: input.target_user_event_id,
            target_user_public_key: input.target_user_public_key,
        },
        signer_event_id: input.authority_admin_id,
        signer_private_key: input.authority_private_key,
    })
    .expect("sign admin grant");
    let admin_id = grant.value.signed_event_id;
    admit(store, protocol, grant);
    admin_id
}

fn create_user_from_admin_invite(
    store: &crate::core::store::Store,
    protocol: &Protocol,
    input: AdminInviteUserInput,
) -> CreatedUser {
    let invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
        created_at_ms: input.timestamp,
        public_key: crypto::ed25519_public_key(&input.invite_private_key),
        workspace_id: input.workspace_id,
        authority_event_id: input.authority_admin_id,
        signer_event_id: input.signer_endpoint_shared_id,
        signer_private_key: input.signer_endpoint_private_key,
    })
    .expect("create admin-authorized user invite");
    let user_invite_id = invite.value.user_invite_id;
    let mut records = admit(store, protocol, invite);

    let user = user::commands::create(user::commands::CreateUser {
        created_at_ms: input.timestamp + 1,
        workspace_id: input.workspace_id,
        public_key: crypto::ed25519_public_key(&input.user_private_key),
        username: input.username.to_string(),
        user_invite_event_id: user_invite_id,
        user_invite_private_key: input.invite_private_key,
    })
    .expect("create invited user");
    let user_id = user.value.user_id;
    let public_key = user.value.public_key;
    records.extend(admit(store, protocol, user));

    CreatedUser {
        user_id,
        user_invite_id,
        public_key,
        user_private_key: input.user_private_key,
        records,
    }
}

fn create_user(
    store: &crate::core::store::Store,
    protocol: &Protocol,
    input: UserInput,
) -> CreatedUser {
    let invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
        created_at_ms: input.timestamp,
        public_key: crypto::ed25519_public_key(&input.invite_private_key),
        workspace_id: input.workspace_id,
        authority_event_id: input.workspace_id,
        signer_event_id: input.workspace_id,
        signer_private_key: input.workspace_private_key,
    })
    .expect("create user invite");
    let user_invite_id = invite.value.user_invite_id;
    let mut records = admit(store, protocol, invite);

    let user = user::commands::create(user::commands::CreateUser {
        created_at_ms: input.timestamp + 1,
        workspace_id: input.workspace_id,
        public_key: crypto::ed25519_public_key(&input.user_private_key),
        username: input.username.to_string(),
        user_invite_event_id: user_invite_id,
        user_invite_private_key: input.invite_private_key,
    })
    .expect("create user");
    let user_id = user.value.user_id;
    let public_key = user.value.public_key;
    records.extend(admit(store, protocol, user));

    CreatedUser {
        user_id,
        user_invite_id,
        public_key,
        user_private_key: input.user_private_key,
        records,
    }
}

fn share_endpoint(
    store: &crate::core::store::Store,
    protocol: &Protocol,
    input: EndpointJoinInput,
) -> EndpointJoin {
    let invite = device_invite::commands::create_with_private_key(
        device_invite::commands::CreateDeviceInvite {
            created_at_ms: input.timestamp,
            workspace_id: input.workspace_id,
            user_authority_event_id: input.user_id,
            user_invite_event_id: input.user_invite_id,
            signer_event_id: input.signer_event_id,
            signer_private_key: input.signer_private_key,
        },
        input.device_invite_private_key,
    )
    .expect("create device invite");
    let device_invite_id = invite.value.device_invite_id;
    let mut records = admit(store, protocol, invite);

    let shared = endpoint_shared::commands::share_endpoint(
        store,
        endpoint_shared::commands::ShareEndpoint {
            created_at_ms: input.timestamp + 1,
            workspace_id: input.workspace_id,
            user_authority_event_id: input.user_id,
            endpoint_id: crypto::ed25519_public_key(&input.endpoint_private_key),
            signing_public_key: crypto::ed25519_public_key(&input.endpoint_private_key),
            device_name: input.device_name.to_string(),
            device_invite_id,
            device_invite_private_key: input.device_invite_private_key,
        },
    )
    .expect("share endpoint");
    let endpoint_shared_id = shared.value.endpoint_shared_id;
    records.extend(admit(store, protocol, shared));

    EndpointJoin {
        endpoint_shared_id,
        endpoint_id: crypto::ed25519_public_key(&input.endpoint_private_key),
        device_invite_id,
        device_invite_private_key: input.device_invite_private_key,
        endpoint_private_key: input.endpoint_private_key,
        records,
    }
}

fn admit<T>(
    store: &crate::core::store::Store,
    protocol: &Protocol,
    output: CommandOutput<T>,
) -> Vec<EventRecord> {
    let records = output
        .events
        .iter()
        .map(|event| event.record().clone())
        .collect::<Vec<_>>();
    worker::run(store, protocol, output).expect("admit command output");
    records
}

fn reversed_records(groups: Vec<Vec<EventRecord>>) -> Vec<EventRecord> {
    groups
        .into_iter()
        .flatten()
        .rev()
        .collect::<Vec<EventRecord>>()
}

fn row_count(store: &crate::core::store::Store, table: crate::core::store::TableName) -> usize {
    store.table_row_count(table).expect("row count")
}

fn assert_admin(
    store: &crate::core::store::Store,
    workspace_id: EventId,
    admin_id: EventId,
    public_key: [u8; 32],
) {
    let key = admin::schema::admin_key(&workspace_id, &admin_id);
    let value = store
        .table_row(admin::schema::ADMINS, &key)
        .expect("read admin row")
        .expect("admin row");
    let row = admin::schema::decode_admin_row(&key, &value).expect("decode admin");
    assert_eq!(row.workspace_id, workspace_id);
    assert_eq!(row.admin_id, admin_id);
    assert_eq!(row.authority_event_id, workspace_id);
    assert_eq!(row.user_event_id, workspace_id);
    assert_eq!(row.public_key, public_key);
}

fn assert_user(
    store: &crate::core::store::Store,
    workspace_id: EventId,
    user_id: EventId,
    username: &str,
) {
    let key = user::schema::user_key(&workspace_id, &user_id);
    let value = store
        .table_row(user::schema::USERS, &key)
        .expect("read user row")
        .expect("user row");
    let row = user::schema::decode_user_row(&key, &value).expect("decode user");
    assert_eq!(row.workspace_id, workspace_id);
    assert_eq!(row.user_id, user_id);
    assert_eq!(row.username, username);
}

fn assert_membership(
    store: &crate::core::store::Store,
    workspace_id: EventId,
    endpoint_id: [u8; 32],
    user_id: EventId,
) {
    let key = endpoint_shared::schema::endpoint_membership_key(endpoint_id, workspace_id);
    let value = store
        .table_row(endpoint_shared::schema::ENDPOINT_MEMBERSHIPS, &key)
        .expect("read endpoint membership")
        .expect("endpoint membership");
    let row =
        endpoint_shared::schema::decode_endpoint_membership_row(&key, &value).expect("decode row");
    assert_eq!(row.endpoint_id, endpoint_id);
    assert_eq!(row.workspace_id, workspace_id);
    assert_eq!(row.user_authority_event_id, user_id);
}
