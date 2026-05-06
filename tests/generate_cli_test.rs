mod cli_harness;

use cli_harness::*;
use topo::core::crypto;
use topo::protocol::event_modules::identity::{
    device_invite, endpoint, endpoint_shared, user, user_invite, workspace,
};
use topo::protocol::event_modules::types::EventId;
use topo::protocol::event_modules::worker;
use topo::protocol::Protocol;

// Invariant: generate cli uses real store and reports applied events.
#[test]
fn generate_cli_uses_real_store_and_reports_applied_events() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "generate.db");
    let workspace_id = create_workspace(&db);
    let workspace_hex = hex_id(workspace_id);

    let generated = assert_success(topo(&["--db", &db, "generate", &workspace_hex, "7", "128"]));
    assert!(generated.contains("generated_events: 7"), "{generated}");
    assert!(generated.contains("applied_events: 7"), "{generated}");
    assert!(generated.contains("event_size_bytes: 128"), "{generated}");
    assert!(generated.contains("first_timestamp: 1"), "{generated}");
    assert!(generated.contains("last_timestamp: 7"), "{generated}");

    let content = assert_success(topo(&["--db", &db, "content-count", &workspace_hex]));
    assert_eq!(line_value(&content, "content_events"), "7");
    assert_eq!(line_value(&content, "content_payload_bytes"), "896");

    let status = assert_success(topo(&["--db", &db, "count"]));
    assert_eq!(line_value(&status, "events"), "12");
    assert_eq!(line_value(&status, "applied_events"), "12");
    assert_eq!(line_value(&status, "ready_events"), "0");
    assert_eq!(line_value(&status, "blocked_events"), "0");
}

fn create_workspace(db: &str) -> EventId {
    let protocol = Protocol::new();
    let store = Protocol::open_store(db).expect("open store");
    let local = endpoint::commands::create_local_keypair();
    let local_keypair = local.value;
    worker::run(&store, &protocol, local).expect("admit local endpoint");

    let workspace_private_key = [7; 32];
    let output = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 1,
        public_key: crypto::ed25519_public_key(&workspace_private_key),
        name: "Generate".to_string(),
    })
    .expect("create workspace");
    let workspace_id = output.value.workspace_id;
    worker::run(&store, &protocol, output).expect("admit workspace");

    let invite_private_key = [8; 32];
    let user_private_key = [9; 32];
    let user_invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
        created_at_ms: 2,
        public_key: crypto::ed25519_public_key(&invite_private_key),
        workspace_id,
        authority_event_id: workspace_id,
        signer_event_id: workspace_id,
        signer_private_key: workspace_private_key,
    })
    .expect("create user invite");
    let user_invite_id = user_invite.value.user_invite_id;
    worker::run(&store, &protocol, user_invite).expect("admit user invite");

    let user = user::commands::create(user::commands::CreateUser {
        created_at_ms: 3,
        workspace_id,
        public_key: crypto::ed25519_public_key(&user_private_key),
        username: "alice".to_string(),
        user_invite_event_id: user_invite_id,
        user_invite_private_key: invite_private_key,
    })
    .expect("create user");
    let user_id = user.value.user_id;
    worker::run(&store, &protocol, user).expect("admit user");

    let device_private_key = [10; 32];
    let device_invite = device_invite::commands::create_with_private_key(
        device_invite::commands::CreateDeviceInvite {
            created_at_ms: 4,
            workspace_id,
            user_authority_event_id: user_id,
            user_invite_event_id: Some(user_invite_id),
            signer_event_id: user_id,
            signer_private_key: user_private_key,
        },
        device_private_key,
    )
    .expect("create device invite");
    let device_invite_id = device_invite.value.device_invite_id;
    worker::run(&store, &protocol, device_invite).expect("admit device invite");

    let endpoint_shared = endpoint_shared::commands::share_endpoint(
        &store,
        endpoint_shared::commands::ShareEndpoint {
            created_at_ms: 5,
            workspace_id,
            user_authority_event_id: user_id,
            endpoint_id: local_keypair.endpoint,
            signing_public_key: local_keypair.signing_public_key,
            device_name: "local".to_string(),
            device_invite_id,
            device_invite_private_key: device_private_key,
        },
    )
    .expect("share endpoint");
    worker::run(&store, &protocol, endpoint_shared).expect("admit endpoint shared");
    workspace_id
}

fn hex_id(id: EventId) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in id {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
